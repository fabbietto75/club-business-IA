import os
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Optional

import bcrypt
import jwt
import requests
import stripe
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy import (
    DECIMAL,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    inspect,
)
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker
from sqlalchemy.sql import text

from .security_plugin import (
    build_google_totp_setup,
    generate_numeric_otp,
    otp_expiration,
    password_security_check,
    verify_google_totp,
)

def _normalize_database_url(url: str) -> str:
    if not url:
        return url
    if url.startswith("postgres://"):
        return "postgresql+psycopg2://" + url[len("postgres://") :]
    if url.startswith("postgresql://") and not url.startswith("postgresql+"):
        return "postgresql+psycopg2://" + url[len("postgresql://") :]
    return url


def _ensure_postgres_ssl(url: str) -> str:
    """Aggiunge sslmode per PostgreSQL (Render e molti host gestiti richiedono SSL)."""
    if not url or not url.startswith("postgresql+"):
        return url
    if "sslmode=" in url:
        return url
    mode = os.getenv("DATABASE_SSLMODE", "require").strip().lower()
    if mode in ("", "disable", "off", "false", "no"):
        return url
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}sslmode={mode}"


DATABASE_URL = _ensure_postgres_ssl(
    _normalize_database_url(
        os.getenv(
            "DATABASE_URL",
            "mysql+pymysql://club_user:club_pass@localhost:3306/club_business_ia",
        )
    )
)
JWT_SECRET = os.getenv("JWT_SECRET", "club_business_ia_secret")
JWT_ALG = "HS256"
ACCESS_TOKEN_MINUTES = 15
REFRESH_TOKEN_DAYS = 30
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
WEBHOOK_AUTH_TOKEN = os.getenv("WEBHOOK_AUTH_TOKEN", "club_webhook_token")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@clubbusinessia.local")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "Admin123!")
ADMIN_NAME = os.getenv("ADMIN_NAME", "Founder Admin")
ALLOWED_TARGETS = {
    x.strip().lower()
    for x in os.getenv(
        "ALLOWED_TARGETS",
        "avvocati,pasticceri,ristoratori,gelatai,parrucchieri,aziende,privati",
    ).split(",")
    if x.strip()
}
REQUIRE_APPROVAL = os.getenv("REQUIRE_APPROVAL", "false").lower() == "true"
THREE_FACTOR_REQUIRED = os.getenv("THREE_FACTOR_REQUIRED", "false").lower() == "true"
EMAIL_OTP_DEV_EXPOSE = os.getenv("EMAIL_OTP_DEV_EXPOSE", "true").lower() == "true"
REQUIRE_REGISTRATION_OTP = os.getenv("REQUIRE_REGISTRATION_OTP", "true").lower() == "true"
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
SITE_CAPACITY = int(os.getenv("SITE_CAPACITY", "200"))
ALLOWED_ORIGINS = [
    o.strip()
    for o in os.getenv(
        "ALLOWED_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000",
    ).split(",")
    if o.strip()
]

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

_engine_kwargs = {"pool_pre_ping": True}
if DATABASE_URL.startswith("postgresql+"):
    _engine_kwargs["pool_recycle"] = 300
engine = create_engine(DATABASE_URL, **_engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(120), nullable=False)
    email = Column(String(190), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="user")
    target_segment = Column(String(80), nullable=False, default="privati")
    is_approved = Column(Boolean, nullable=False, default=True)
    mfa_enabled = Column(Boolean, nullable=False, default=False)
    mfa_secret = Column(String(255), nullable=True)
    mfa_temp_secret = Column(String(255), nullable=True)
    email_otp_code = Column(String(20), nullable=True)
    email_otp_expires_at = Column(DateTime, nullable=True)
    avatar_url = Column(String(500), nullable=True)
    profile_mode = Column(String(20), nullable=False, default="privato")
    company_photo_url = Column(String(500), nullable=True)
    coins = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class CoinTransaction(Base):
    __tablename__ = "coin_transactions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    amount = Column(Integer, nullable=False)
    reason = Column(String(120), nullable=False, default="mission")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    user = relationship("User")


class AuthToken(Base):
    __tablename__ = "auth_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    token_jti = Column(String(120), unique=True, nullable=False, index=True)
    token_type = Column(String(20), nullable=False)  # access | refresh
    revoked = Column(Boolean, nullable=False, default=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    user = relationship("User")


class RegistrationOtp(Base):
    __tablename__ = "registration_otps"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(190), nullable=False, index=True)
    otp_code = Column(String(20), nullable=False)
    target_segment = Column(String(80), nullable=False, default="privati")
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class SiteSeat(Base):
    __tablename__ = "site_seats"

    id = Column(Integer, primary_key=True, index=True)
    seat_number = Column(Integer, unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    status = Column(String(20), nullable=False, default="free")
    assigned_at = Column(DateTime, nullable=True)
    user = relationship("User")


class FeatureToggle(Base):
    __tablename__ = "feature_toggles"

    id = Column(Integer, primary_key=True, index=True)
    feature_key = Column(String(100), unique=True, nullable=False, index=True)
    enabled = Column(Boolean, nullable=False, default=True)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Mission(Base):
    __tablename__ = "missions"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(160), nullable=False)
    description = Column(Text, nullable=False, default="")
    reward_coins = Column(Integer, nullable=False, default=10)
    status = Column(String(20), nullable=False, default="active")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class UserMission(Base):
    __tablename__ = "user_missions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    mission_id = Column(Integer, ForeignKey("missions.id"), nullable=False)
    status = Column(String(20), nullable=False, default="completed")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    user = relationship("User")
    mission = relationship("Mission")


class CommunityPost(Base):
    __tablename__ = "community_posts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    user = relationship("User")


class Product(Base):
    __tablename__ = "products"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(160), nullable=False)
    price = Column(DECIMAL(10, 2), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Order(Base):
    __tablename__ = "orders"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    product_id = Column(Integer, ForeignKey("products.id"), nullable=False)
    total = Column(DECIMAL(10, 2), nullable=False)
    status = Column(String(20), nullable=False, default="created")
    stripe_session_id = Column(String(255), nullable=True)
    stripe_payment_intent = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    user = relationship("User")
    product = relationship("Product")


class EcommerceProduct(Base):
    __tablename__ = "ecommerce_products"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(180), nullable=False)
    description = Column(Text, nullable=False, default="")
    showcase_text = Column(String(255), nullable=False, default="")
    category = Column(String(120), nullable=False, default="general")
    image_url = Column(String(500), nullable=True)
    price = Column(DECIMAL(10, 2), nullable=False)
    stock = Column(Integer, nullable=False, default=0)
    status = Column(String(20), nullable=False, default="active")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class CartItem(Base):
    __tablename__ = "cart_items"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    ecommerce_product_id = Column(Integer, ForeignKey("ecommerce_products.id"), nullable=False)
    quantity = Column(Integer, nullable=False, default=1)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    user = relationship("User")
    product = relationship("EcommerceProduct")


class UserProduct(Base):
    __tablename__ = "user_products"

    id = Column(Integer, primary_key=True, index=True)
    owner_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    title = Column(String(180), nullable=False)
    description = Column(Text, nullable=False, default="")
    price = Column(DECIMAL(10, 2), nullable=False, default=0)
    status = Column(String(20), nullable=False, default="draft")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    owner = relationship("User")


class UserCourse(Base):
    __tablename__ = "user_courses"

    id = Column(Integer, primary_key=True, index=True)
    owner_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    title = Column(String(180), nullable=False)
    description = Column(Text, nullable=False, default="")
    price = Column(DECIMAL(10, 2), nullable=False, default=0)
    status = Column(String(20), nullable=False, default="draft")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    owner = relationship("User")


class CourseEnrollment(Base):
    __tablename__ = "course_enrollments"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    course_id = Column(Integer, ForeignKey("user_courses.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    user = relationship("User")
    course = relationship("UserCourse")


class Workspace(Base):
    __tablename__ = "workspaces"

    id = Column(Integer, primary_key=True, index=True)
    owner_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String(180), nullable=False)
    description = Column(Text, nullable=False, default="")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    owner = relationship("User")
    notes = relationship(
        "WorkspaceNote", back_populates="workspace", cascade="all, delete-orphan"
    )
    social_posts = relationship(
        "WorkspacePost", back_populates="workspace", cascade="all, delete-orphan"
    )


class WorkspacePost(Base):
    __tablename__ = "workspace_posts"

    id = Column(Integer, primary_key=True, index=True)
    workspace_id = Column(Integer, ForeignKey("workspaces.id"), nullable=False, index=True)
    owner_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    workspace = relationship("Workspace", back_populates="social_posts")
    owner = relationship("User")


class PlatformNotification(Base):
    __tablename__ = "platform_notifications"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    kind = Column(String(40), nullable=False)
    title = Column(String(200), nullable=False)
    body = Column(Text, nullable=False, default="")
    ref_type = Column(String(40), nullable=True)
    ref_id = Column(Integer, nullable=True)
    read_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    user = relationship("User")


class WorkspaceNote(Base):
    __tablename__ = "workspace_notes"

    id = Column(Integer, primary_key=True, index=True)
    workspace_id = Column(Integer, ForeignKey("workspaces.id"), nullable=False, index=True)
    owner_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    title = Column(String(200), nullable=False, default="")
    content = Column(Text, nullable=False, default="")
    note_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    reminder_at = Column(DateTime, nullable=True)
    is_done = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    workspace = relationship("Workspace", back_populates="notes")
    owner = relationship("User")


class BusinessProfile(Base):
    __tablename__ = "business_profiles"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    level = Column(String(30), nullable=False, default="starter_seller")
    points = Column(Integer, nullable=False, default=0)
    direct_referrals = Column(Integer, nullable=False, default=0)
    sponsor_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    user = relationship("User", foreign_keys=[user_id])


class BusinessAd(Base):
    __tablename__ = "business_ads"

    id = Column(Integer, primary_key=True, index=True)
    owner_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    title = Column(String(180), nullable=False)
    description = Column(Text, nullable=False, default="")
    channel = Column(String(80), nullable=False, default="social")
    budget = Column(DECIMAL(10, 2), nullable=False, default=0)
    status = Column(String(20), nullable=False, default="draft")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    owner = relationship("User")


class TargetOffer(Base):
    __tablename__ = "target_offers"

    id = Column(Integer, primary_key=True, index=True)
    seller_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    seller_target = Column(String(80), nullable=False)
    title = Column(String(180), nullable=False)
    description = Column(Text, nullable=False, default="")
    coin_price = Column(Integer, nullable=False, default=1)
    quantity_available = Column(Integer, nullable=False, default=0)
    status = Column(String(20), nullable=False, default="active")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    seller = relationship("User")


class OfferRedemption(Base):
    __tablename__ = "offer_redemptions"

    id = Column(Integer, primary_key=True, index=True)
    offer_id = Column(Integer, ForeignKey("target_offers.id"), nullable=False)
    buyer_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    seller_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    quantity = Column(Integer, nullable=False, default=1)
    total_coins = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    offer = relationship("TargetOffer")
    buyer = relationship("User", foreign_keys=[buyer_user_id])
    seller = relationship("User", foreign_keys=[seller_user_id])


class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    target_segment: str
    registration_otp_code: Optional[str] = None


class LoginIn(BaseModel):
    email: EmailStr
    password: str
    totp_code: Optional[str] = None
    email_otp_code: Optional[str] = None


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: int
    name: str
    email: EmailStr
    role: str
    target_segment: str
    avatar_url: Optional[str] = None
    profile_mode: str = "privato"
    company_photo_url: Optional[str] = None
    coins: int

    class Config:
        from_attributes = True


class CoinUpdate(BaseModel):
    amount: int
    reason: Optional[str] = "mission"


class MissionCreate(BaseModel):
    title: str
    description: Optional[str] = ""
    reward_coins: int = 10


class MissionOut(BaseModel):
    id: int
    title: str
    description: str
    reward_coins: int
    status: str

    class Config:
        from_attributes = True


class CommunityPostCreate(BaseModel):
    content: str


class AccountProfileUpdate(BaseModel):
    name: str
    target_segment: str
    avatar_url: Optional[str] = None
    profile_mode: str = "privato"
    company_photo_url: Optional[str] = None


class WorkspaceNoteIn(BaseModel):
    title: str = ""
    content: str
    note_at: Optional[datetime] = None
    reminder_at: Optional[datetime] = None


class WorkspaceNoteUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    note_at: Optional[datetime] = None
    reminder_at: Optional[datetime] = None
    is_done: Optional[bool] = None


class WorkspacePostIn(BaseModel):
    content: str


class ProductCreate(BaseModel):
    name: str
    price: float


class OrderCreate(BaseModel):
    product_id: int
    coins_to_spend: int = 0


class RefreshIn(BaseModel):
    refresh_token: str


class AdminUserRoleUpdate(BaseModel):
    role: str


class AdminUserApprovalUpdate(BaseModel):
    is_approved: bool


class FeatureToggleUpdate(BaseModel):
    enabled: bool


class MissionUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    reward_coins: Optional[int] = None
    status: Optional[str] = None


class EcommerceProductCreate(BaseModel):
    title: str
    description: str = ""
    showcase_text: str = ""
    category: str = "general"
    image_url: Optional[str] = None
    price: float
    stock: int = 0


class EcommerceProductUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    showcase_text: Optional[str] = None
    category: Optional[str] = None
    image_url: Optional[str] = None
    price: Optional[float] = None
    stock: Optional[int] = None
    status: Optional[str] = None


class CartAddIn(BaseModel):
    ecommerce_product_id: int
    quantity: int = 1


class CartUpdateIn(BaseModel):
    quantity: int


class MfaEnableIn(BaseModel):
    totp_code: str


class RequestEmailOtpIn(BaseModel):
    email: EmailStr
    password: str


class RequestRegistrationOtpIn(BaseModel):
    email: EmailStr
    target_segment: str


class AIChatIn(BaseModel):
    message: str


class CapacityOut(BaseModel):
    total_seats: int
    occupied_seats: int
    free_seats: int
    occupancy_percent: float


class UserProductIn(BaseModel):
    title: str
    description: str = ""
    price: float = 0
    status: str = "draft"


class UserCourseIn(BaseModel):
    title: str
    description: str = ""
    price: float = 0
    status: str = "draft"


class WorkspaceIn(BaseModel):
    name: str
    description: str = ""


class BusinessJoinIn(BaseModel):
    sponsor_user_id: Optional[int] = None


class BusinessAdIn(BaseModel):
    title: str
    description: str = ""
    channel: str = "social"
    budget: float = 0
    status: str = "draft"


class TargetOfferIn(BaseModel):
    title: str
    description: str = ""
    coin_price: int = 1
    quantity_available: int = 1


class OfferRedeemIn(BaseModel):
    quantity: int = 1


app = FastAPI(title="Club Business IA API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _notify_users_except(
    db: Session,
    exclude_user_id: int,
    kind: str,
    title: str,
    body: str,
    ref_type: Optional[str] = None,
    ref_id: Optional[int] = None,
) -> None:
    rows = (
        db.query(User.id)
        .filter(User.is_approved.is_(True), User.id != exclude_user_id)
        .all()
    )
    for (uid,) in rows:
        db.add(
            PlatformNotification(
                user_id=uid,
                kind=kind,
                title=title[:200],
                body=(body or "")[:4000],
                ref_type=ref_type,
                ref_id=ref_id,
            )
        )


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.on_event("startup")
def on_startup() -> None:
    Base.metadata.create_all(bind=engine)
    ensure_schema_updates()
    seed_default_data()


def ensure_schema_updates() -> None:
    inspector = inspect(engine)
    user_columns = {column["name"] for column in inspector.get_columns("users")}
    is_pg = engine.dialect.name == "postgresql"
    dt_null = "TIMESTAMP NULL" if is_pg else "DATETIME NULL"
    missing_user_columns = {
        "target_segment": "VARCHAR(80) NOT NULL DEFAULT 'privati'",
        "is_approved": "BOOLEAN NOT NULL DEFAULT TRUE",
        "mfa_enabled": "BOOLEAN NOT NULL DEFAULT FALSE",
        "mfa_secret": "VARCHAR(255) NULL",
        "mfa_temp_secret": "VARCHAR(255) NULL",
        "email_otp_code": "VARCHAR(20) NULL",
        "email_otp_expires_at": dt_null,
        "avatar_url": "VARCHAR(500) NULL",
        "profile_mode": "VARCHAR(20) NOT NULL DEFAULT 'privato'",
        "company_photo_url": "VARCHAR(500) NULL",
    }

    with engine.begin() as conn:
        for column_name, column_definition in missing_user_columns.items():
            if column_name in user_columns:
                continue
            conn.execute(
                text(
                    f"ALTER TABLE users ADD COLUMN {column_name} {column_definition}"
                )
            )


def seed_default_data() -> None:
    db = SessionLocal()
    try:
        if db.query(User).filter(User.email == ADMIN_EMAIL.lower()).first() is None:
            db.add(
                User(
                    name=ADMIN_NAME,
                    email=ADMIN_EMAIL.lower(),
                    password_hash=hash_password(ADMIN_PASSWORD),
                    role="admin",
                    target_segment="aziende",
                    is_approved=True,
                    coins=100,
                )
            )
        if db.query(Product).count() == 0:
            db.add_all(
                [
                    Product(name="Corso IA per Business", price=Decimal("97.00")),
                    Product(name="Template Social Premium", price=Decimal("29.00")),
                ]
            )
        if db.query(EcommerceProduct).count() == 0:
            db.add_all(
                [
                    EcommerceProduct(
                        title="Pacchetto Social Avvocati",
                        description="Template, copy e strategia social per studi legali.",
                        showcase_text="Offerta dedicata al target avvocati",
                        category="avvocati",
                        price=Decimal("149.00"),
                        stock=50,
                        status="active",
                    ),
                    EcommerceProduct(
                        title="Kit Menu Smart Ristoranti",
                        description="Bundle digitale per menu, promo e campagne locali.",
                        showcase_text="Perfetto per aumentare prenotazioni",
                        category="ristoratori",
                        price=Decimal("89.00"),
                        stock=100,
                        status="active",
                    ),
                ]
            )
        if db.query(Mission).count() == 0:
            db.add_all(
                [
                    Mission(
                        title="Completa il profilo",
                        description="Aggiungi le informazioni base del tuo account.",
                        reward_coins=10,
                    ),
                    Mission(
                        title="Pubblica il primo post",
                        description="Crea un post nella community.",
                        reward_coins=5,
                    ),
                ]
            )
        if db.query(FeatureToggle).count() == 0:
            db.add_all(
                [
                    FeatureToggle(feature_key="ai_chat", enabled=True),
                    FeatureToggle(feature_key="community", enabled=True),
                    FeatureToggle(feature_key="missions", enabled=True),
                    FeatureToggle(feature_key="ecommerce", enabled=True),
                    FeatureToggle(feature_key="payments", enabled=True),
                ]
            )
        seat_count = db.query(SiteSeat).count()
        if seat_count < SITE_CAPACITY:
            start = seat_count + 1
            for number in range(start, SITE_CAPACITY + 1):
                db.add(SiteSeat(seat_number=number, status="free"))
        db.commit()
    finally:
        db.close()


def hash_password(raw_password: str) -> str:
    return bcrypt.hashpw(raw_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(raw_password: str, password_hash: str) -> bool:
    # Compatibilita: accetta hash bcrypt nuovi e sha256 legacy.
    if password_hash.startswith("$2"):
        return bcrypt.checkpw(raw_password.encode("utf-8"), password_hash.encode("utf-8"))
    import hashlib

    return hashlib.sha256(raw_password.encode("utf-8")).hexdigest() == password_hash


def create_token_record(db: Session, user: User, token_type: str, expires_at: datetime) -> str:
    token_jti = str(uuid.uuid4())
    db.add(
        AuthToken(
            user_id=user.id,
            token_jti=token_jti,
            token_type=token_type,
            expires_at=expires_at,
        )
    )
    return token_jti


def create_token(user: User, token_type: str, expires_in: timedelta, jti: str) -> str:
    exp = datetime.now(timezone.utc) + expires_in
    payload = {"sub": user.id, "role": user.role, "exp": exp, "type": token_type, "jti": jti}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Token non valido") from exc


def issue_auth_tokens(db: Session, user: User) -> TokenOut:
    access_exp = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_MINUTES)
    refresh_exp = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_DAYS)
    access_jti = create_token_record(db, user, "access", access_exp)
    refresh_jti = create_token_record(db, user, "refresh", refresh_exp)
    db.commit()
    return TokenOut(
        access_token=create_token(
            user=user,
            token_type="access",
            expires_in=timedelta(minutes=ACCESS_TOKEN_MINUTES),
            jti=access_jti,
        ),
        refresh_token=create_token(
            user=user,
            token_type="refresh",
            expires_in=timedelta(days=REFRESH_TOKEN_DAYS),
            jti=refresh_jti,
        ),
    )


def validate_target_segment(target_segment: str) -> str:
    cleaned = target_segment.strip().lower()
    if cleaned not in ALLOWED_TARGETS:
        raise HTTPException(
            status_code=403,
            detail="Target non autorizzato. Accesso consentito solo ai segmenti del club.",
        )
    return cleaned


def revoke_token_jti(db: Session, jti: Optional[str]) -> None:
    if not jti:
        return
    record = db.query(AuthToken).filter(AuthToken.token_jti == jti).first()
    if record:
        record.revoked = True
        db.commit()


def token_is_valid(db: Session, payload: dict, expected_type: str) -> bool:
    jti = payload.get("jti")
    if payload.get("type") != expected_type or not jti:
        return False
    record = db.query(AuthToken).filter(AuthToken.token_jti == jti).first()
    return bool(record and not record.revoked and record.token_type == expected_type)


def get_current_user(
    db: Session = Depends(get_db), authorization: Optional[str] = Header(default=None)
) -> User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Autenticazione richiesta")
    token = authorization.replace("Bearer ", "", 1)
    payload = decode_token(token)
    if not token_is_valid(db, payload, "access"):
        raise HTTPException(status_code=401, detail="Token revocato o scaduto")
    user_id = payload.get("sub")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=401, detail="Utente non trovato")
    return user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Ruolo admin richiesto")
    return current_user


def require_owner(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "owner":
        raise HTTPException(status_code=403, detail="Accesso consentito solo al proprietario")
    return current_user


def feature_enabled_or_503(db: Session, key: str) -> None:
    item = db.query(FeatureToggle).filter(FeatureToggle.feature_key == key).first()
    if item and not item.enabled:
        raise HTTPException(status_code=503, detail=f"Modulo '{key}' temporaneamente disattivato")


def local_chat_fallback(message: str) -> str:
    q = message.lower()
    if "registr" in q:
        return "Per registrarti: seleziona target, richiedi OTP registrazione, inserisci OTP e completa il form."
    if "2fa" in q or "otp" in q or "sicurezza" in q:
        return "Per la sicurezza: attiva Google Authenticator da setup MFA e usa OTP email se la 3FA e attiva."
    if "carrello" in q or "ordine" in q or "ecommerce" in q:
        return "Per vendere: carica i prodotti in vetrina, usa carrello e completa il checkout."
    if "admin" in q:
        return "Nel pannello admin puoi gestire utenti, approvazioni, missioni, ordini e prodotti."
    return "Sono l'assistente Club Business IA. Posso aiutarti su registrazione, sicurezza, e-commerce e pannello admin."


def ai_chat_completion(message: str) -> str:
    if not OPENAI_API_KEY:
        return local_chat_fallback(message)

    payload = {
        "model": OPENAI_MODEL,
        "messages": [
            {
                "role": "system",
                "content": "Sei l'assistente di Club Business IA. Rispondi in italiano in modo chiaro e concreto.",
            },
            {"role": "user", "content": message},
        ],
        "temperature": 0.4,
    }
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }
    try:
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            json=payload,
            headers=headers,
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"].strip()
    except Exception:
        return local_chat_fallback(message)


def resolve_business_level(points: int) -> str:
    if points >= 120:
        return "executive_partner"
    if points >= 80:
        return "area_director"
    if points >= 50:
        return "business_manager"
    if points >= 25:
        return "growth_manager"
    if points >= 10:
        return "smart_vendor"
    return "starter_seller"


def get_capacity_stats(db: Session) -> dict:
    total = db.query(SiteSeat).count()
    occupied = db.query(SiteSeat).filter(SiteSeat.status == "occupied").count()
    free = max(total - occupied, 0)
    percent = round((occupied / total) * 100, 2) if total > 0 else 0.0
    return {
        "total_seats": total,
        "occupied_seats": occupied,
        "free_seats": free,
        "occupancy_percent": percent,
    }


@app.get("/health")
def health():
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(status_code=503, detail="database_unavailable") from exc
    return {"status": "ok", "service": "python-api", "database": "ok"}


@app.post("/ai/chat")
def ai_chat(payload: AIChatIn, db: Session = Depends(get_db)):
    feature_enabled_or_503(db, "ai_chat")
    message = payload.message.strip()
    if not message:
        raise HTTPException(status_code=400, detail="Messaggio vuoto")
    reply = ai_chat_completion(message)
    return {"reply": reply, "model": OPENAI_MODEL if OPENAI_API_KEY else "fallback-local"}


@app.post("/users", response_model=UserOut)
def create_user(payload: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=409, detail="Email gia registrata")

    ok, reason = password_security_check(payload.password)
    if not ok:
        raise HTTPException(status_code=400, detail=reason)

    segment = validate_target_segment(payload.target_segment)
    if REQUIRE_REGISTRATION_OTP:
        if not payload.registration_otp_code:
            raise HTTPException(status_code=400, detail="OTP registrazione obbligatorio")
        reg_otp = (
            db.query(RegistrationOtp)
            .filter(
                RegistrationOtp.email == str(payload.email).lower(),
                RegistrationOtp.used == False,  # noqa: E712
            )
            .order_by(RegistrationOtp.id.desc())
            .first()
        )
        if (
            not reg_otp
            or reg_otp.otp_code != payload.registration_otp_code
            or reg_otp.expires_at < datetime.utcnow()
            or reg_otp.target_segment != segment
        ):
            raise HTTPException(status_code=401, detail="OTP registrazione non valido o scaduto")
        reg_otp.used = True

    user = User(
        name=payload.name.strip(),
        email=str(payload.email).lower(),
        password_hash=hash_password(payload.password),
        role="user",
        target_segment=segment,
        is_approved=not REQUIRE_APPROVAL,
        coins=5,  # Bonus registrazione
    )

    free_seat = (
        db.query(SiteSeat)
        .filter(SiteSeat.status == "free")
        .order_by(SiteSeat.seat_number.asc())
        .first()
    )
    if not free_seat:
        raise HTTPException(
            status_code=409,
            detail=f"Posti esauriti: capienza massima {SITE_CAPACITY} utenti raggiunta",
        )

    db.add(user)
    db.flush()
    free_seat.user_id = user.id
    free_seat.status = "occupied"
    free_seat.assigned_at = datetime.utcnow()
    db.commit()
    db.refresh(user)
    return user


@app.get("/site/capacity", response_model=CapacityOut)
def site_capacity(db: Session = Depends(get_db)):
    stats = get_capacity_stats(db)
    return CapacityOut(**stats)


@app.get("/admin/site/capacity", response_model=CapacityOut)
def admin_site_capacity(
    db: Session = Depends(get_db), _admin: User = Depends(require_admin)
):
    stats = get_capacity_stats(db)
    return CapacityOut(**stats)


@app.post("/auth/registration/request-otp")
def request_registration_otp(payload: RequestRegistrationOtpIn, db: Session = Depends(get_db)):
    segment = validate_target_segment(payload.target_segment)
    email = str(payload.email).lower()
    otp_code = generate_numeric_otp(6)
    db.add(
        RegistrationOtp(
            email=email,
            otp_code=otp_code,
            target_segment=segment,
            expires_at=otp_expiration(10),
            used=False,
        )
    )
    db.commit()
    response = {"status": "ok", "message": "OTP registrazione generato e inviato via email"}
    if EMAIL_OTP_DEV_EXPOSE:
        response["dev_registration_otp_code"] = otp_code
    return response


@app.post("/auth/login", response_model=TokenOut)
def login(payload: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == str(payload.email).lower()).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Credenziali non valide")
    if not user.is_approved:
        raise HTTPException(status_code=403, detail="Account in attesa di approvazione admin")
    validate_target_segment(user.target_segment)
    if user.mfa_enabled:
        if not payload.totp_code:
            raise HTTPException(status_code=401, detail="Codice Google Authenticator richiesto")
        if not verify_google_totp(user.mfa_secret, payload.totp_code):
            raise HTTPException(status_code=401, detail="Codice Google Authenticator non valido")
        if THREE_FACTOR_REQUIRED:
            if not payload.email_otp_code:
                raise HTTPException(status_code=401, detail="Codice OTP email richiesto")
            if (
                user.email_otp_code != payload.email_otp_code
                or not user.email_otp_expires_at
                or user.email_otp_expires_at < datetime.utcnow()
            ):
                raise HTTPException(status_code=401, detail="Codice OTP email non valido o scaduto")
            user.email_otp_code = None
            user.email_otp_expires_at = None
            db.commit()
    return issue_auth_tokens(db, user)


@app.post("/auth/request-email-otp")
def request_email_otp(payload: RequestEmailOtpIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == str(payload.email).lower()).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Credenziali non valide")
    otp_code = f"{uuid.uuid4().int % 1000000:06d}"
    user.email_otp_code = otp_code
    user.email_otp_expires_at = datetime.utcnow() + timedelta(minutes=10)
    db.commit()
    # In produzione: inviare OTP via provider email e non restituire mai il codice.
    response = {"status": "ok", "message": "OTP generato e inviato via email"}
    if EMAIL_OTP_DEV_EXPOSE:
        response["dev_otp_code"] = otp_code
    return response


@app.post("/auth/refresh", response_model=TokenOut)
def refresh_tokens(payload: RefreshIn, db: Session = Depends(get_db)):
    token_payload = decode_token(payload.refresh_token)
    if not token_is_valid(db, token_payload, "refresh"):
        raise HTTPException(status_code=401, detail="Refresh token non valido")
    user = db.get(User, token_payload.get("sub"))
    if not user:
        raise HTTPException(status_code=401, detail="Utente non trovato")
    revoke_token_jti(db, token_payload.get("jti"))
    return issue_auth_tokens(db, user)


@app.post("/auth/logout")
def logout(
    payload: Optional[RefreshIn] = None,
    db: Session = Depends(get_db),
    authorization: Optional[str] = Header(default=None),
):
    if authorization and authorization.startswith("Bearer "):
        access_payload = decode_token(authorization.replace("Bearer ", "", 1))
        revoke_token_jti(db, access_payload.get("jti"))
    if payload and payload.refresh_token:
        refresh_payload = decode_token(payload.refresh_token)
        revoke_token_jti(db, refresh_payload.get("jti"))
    return {"status": "ok"}


@app.get("/auth/me", response_model=UserOut)
def auth_me(current_user: User = Depends(get_current_user)):
    return current_user


@app.patch("/account/profile", response_model=UserOut)
def update_account_profile(
    payload: AccountProfileUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    allowed = {x.strip().lower() for x in ALLOWED_TARGETS.split(",") if x.strip()}
    target_segment = payload.target_segment.strip().lower()
    if target_segment not in allowed:
        raise HTTPException(status_code=400, detail="Target non consentito")

    name = payload.name.strip()
    if len(name) < 2:
        raise HTTPException(status_code=400, detail="Nome troppo corto")

    current_user.name = name
    current_user.target_segment = target_segment
    current_user.avatar_url = (payload.avatar_url or "").strip() or None
    mode = (payload.profile_mode or "privato").strip().lower()
    if mode not in {"privato", "azienda"}:
        raise HTTPException(status_code=400, detail="profile_mode deve essere privato o azienda")
    current_user.profile_mode = mode
    current_user.company_photo_url = (payload.company_photo_url or "").strip() or None
    db.commit()
    db.refresh(current_user)
    return current_user


@app.post("/auth/mfa/setup")
def mfa_setup(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    setup = build_google_totp_setup(current_user.email)
    current_user.mfa_temp_secret = setup["secret"]
    db.commit()
    return {
        "secret": setup["secret"],
        "otpauth_uri": setup["otpauth_uri"],
        "message": "Scansiona il codice in Google Authenticator e poi conferma con /auth/mfa/enable",
    }


@app.post("/auth/mfa/enable")
def mfa_enable(
    payload: MfaEnableIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not current_user.mfa_temp_secret:
        raise HTTPException(status_code=400, detail="Setup MFA non inizializzato")
    if not verify_google_totp(current_user.mfa_temp_secret, payload.totp_code):
        raise HTTPException(status_code=401, detail="Codice MFA non valido")
    current_user.mfa_secret = current_user.mfa_temp_secret
    current_user.mfa_temp_secret = None
    current_user.mfa_enabled = True
    db.commit()
    return {"status": "ok", "mfa_enabled": True}


@app.post("/auth/mfa/disable")
def mfa_disable(
    payload: MfaEnableIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not current_user.mfa_enabled or not current_user.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA non attivo")
    if not verify_google_totp(current_user.mfa_secret, payload.totp_code):
        raise HTTPException(status_code=401, detail="Codice MFA non valido")
    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    current_user.mfa_temp_secret = None
    db.commit()
    return {"status": "ok", "mfa_enabled": False}


@app.get("/users/{user_id}", response_model=UserOut)
def get_user(user_id: int, db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Utente non trovato")
    return user


@app.get("/admin/users", response_model=list[UserOut])
def admin_list_users(db: Session = Depends(get_db), _owner: User = Depends(require_owner)):
    return db.query(User).order_by(User.id.desc()).limit(200).all()


@app.patch("/admin/users/{user_id}/role", response_model=UserOut)
def admin_update_role(
    user_id: int,
    payload: AdminUserRoleUpdate,
    db: Session = Depends(get_db),
    _owner: User = Depends(require_owner),
):
    if payload.role not in {"user", "admin"}:
        raise HTTPException(status_code=400, detail="Ruolo non valido")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Utente non trovato")
    user.role = payload.role
    db.commit()
    db.refresh(user)
    return user


@app.patch("/admin/users/{user_id}/approval", response_model=UserOut)
def admin_update_approval(
    user_id: int,
    payload: AdminUserApprovalUpdate,
    db: Session = Depends(get_db),
    _owner: User = Depends(require_owner),
):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Utente non trovato")
    user.is_approved = payload.is_approved
    db.commit()
    db.refresh(user)
    return user


@app.post("/users/{user_id}/coins", response_model=UserOut)
def add_coins(
    user_id: int,
    payload: CoinUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Utente non trovato")
    if current_user.id != user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Operazione non consentita")

    user.coins += payload.amount
    if user.coins < 0:
        user.coins = 0
    transaction = CoinTransaction(
        user_id=user.id,
        amount=payload.amount,
        reason=payload.reason or "mission",
    )
    db.add(transaction)

    db.commit()
    db.refresh(user)
    return user


@app.get("/wallet/me")
def wallet_me(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    txs = (
        db.query(CoinTransaction)
        .filter(CoinTransaction.user_id == current_user.id)
        .order_by(CoinTransaction.id.desc())
        .limit(20)
        .all()
    )
    return {
        "user_id": current_user.id,
        "coins": current_user.coins,
        "transactions": [
            {
                "id": tx.id,
                "amount": tx.amount,
                "reason": tx.reason,
                "created_at": tx.created_at.isoformat(),
            }
            for tx in txs
        ],
    }


@app.post("/missions", response_model=MissionOut)
def create_mission(
    payload: MissionCreate,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    feature_enabled_or_503(db, "missions")
    mission = Mission(
        title=payload.title.strip(),
        description=(payload.description or "").strip(),
        reward_coins=max(payload.reward_coins, 0),
    )
    db.add(mission)
    db.commit()
    db.refresh(mission)
    return mission


@app.patch("/admin/missions/{mission_id}", response_model=MissionOut)
def update_mission(
    mission_id: int,
    payload: MissionUpdate,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    feature_enabled_or_503(db, "missions")
    mission = db.get(Mission, mission_id)
    if not mission:
        raise HTTPException(status_code=404, detail="Missione non trovata")
    if payload.title is not None:
        mission.title = payload.title.strip()
    if payload.description is not None:
        mission.description = payload.description.strip()
    if payload.reward_coins is not None:
        mission.reward_coins = max(payload.reward_coins, 0)
    if payload.status is not None:
        if payload.status not in {"active", "inactive"}:
            raise HTTPException(status_code=400, detail="Status non valido")
        mission.status = payload.status
    db.commit()
    db.refresh(mission)
    return mission


@app.delete("/admin/missions/{mission_id}")
def delete_mission(
    mission_id: int, db: Session = Depends(get_db), _admin: User = Depends(require_admin)
):
    feature_enabled_or_503(db, "missions")
    mission = db.get(Mission, mission_id)
    if not mission:
        raise HTTPException(status_code=404, detail="Missione non trovata")
    mission.status = "inactive"
    db.commit()
    return {"status": "ok"}


@app.get("/missions", response_model=list[MissionOut])
def list_missions(db: Session = Depends(get_db)):
    feature_enabled_or_503(db, "missions")
    return db.query(Mission).filter(Mission.status == "active").all()


@app.post("/missions/{mission_id}/complete", response_model=UserOut)
def complete_mission(
    mission_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    feature_enabled_or_503(db, "missions")
    mission = db.get(Mission, mission_id)
    if not mission or mission.status != "active":
        raise HTTPException(status_code=404, detail="Missione non trovata")

    exists = (
        db.query(UserMission)
        .filter(UserMission.user_id == current_user.id, UserMission.mission_id == mission_id)
        .first()
    )
    if exists:
        raise HTTPException(status_code=409, detail="Missione gia completata")

    db.add(UserMission(user_id=current_user.id, mission_id=mission_id, status="completed"))
    db.add(
        CoinTransaction(
            user_id=current_user.id, amount=mission.reward_coins, reason="mission_completed"
        )
    )
    current_user.coins += mission.reward_coins
    db.commit()
    db.refresh(current_user)
    return current_user


@app.post("/community/posts")
def create_post(
    payload: CommunityPostCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    feature_enabled_or_503(db, "community")
    content = payload.content.strip()
    if len(content) < 3:
        raise HTTPException(status_code=400, detail="Contenuto troppo corto")
    post = CommunityPost(user_id=current_user.id, content=content)
    db.add(post)
    db.commit()
    db.refresh(post)
    _notify_users_except(
        db,
        current_user.id,
        "community_post",
        "Nuovo messaggio in chat",
        f"{current_user.name}: {content[:280]}",
        "community_post",
        post.id,
    )
    db.commit()
    return {"status": "created"}


@app.get("/community/posts")
def list_posts(db: Session = Depends(get_db)):
    feature_enabled_or_503(db, "community")
    posts = db.query(CommunityPost).order_by(CommunityPost.id.desc()).limit(50).all()
    out = []
    for p in posts:
        u = db.get(User, p.user_id)
        out.append(
            {
                "id": p.id,
                "user_id": p.user_id,
                "author_name": u.name if u else "?",
                "author_avatar_url": u.avatar_url if u else None,
                "author_profile_mode": getattr(u, "profile_mode", None) or "privato",
                "author_company_photo_url": getattr(u, "company_photo_url", None) if u else None,
                "content": p.content,
                "created_at": p.created_at.isoformat(),
            }
        )
    return out


@app.get("/vitrina/products")
def vitrina_products(
    db: Session = Depends(get_db), limit: int = Query(100, ge=1, le=200)
):
    rows = (
        db.query(UserProduct)
        .filter(UserProduct.status == "published")
        .order_by(UserProduct.id.desc())
        .limit(limit)
        .all()
    )
    out = []
    for p in rows:
        u = db.get(User, p.owner_user_id)
        if not u:
            continue
        out.append(
            {
                "id": p.id,
                "title": p.title,
                "description": p.description,
                "price": float(p.price),
                "created_at": p.created_at.isoformat(),
                "seller": {
                    "id": u.id,
                    "name": u.name,
                    "target_segment": u.target_segment,
                    "profile_mode": getattr(u, "profile_mode", None) or "privato",
                    "avatar_url": u.avatar_url,
                    "company_photo_url": getattr(u, "company_photo_url", None),
                },
            }
        )
    return out


@app.get("/notifications/me")
def my_notifications(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    unread_only: bool = Query(False),
):
    q = db.query(PlatformNotification).filter(
        PlatformNotification.user_id == current_user.id
    )
    if unread_only:
        q = q.filter(PlatformNotification.read_at.is_(None))
    rows = q.order_by(PlatformNotification.id.desc()).limit(100).all()
    return [
        {
            "id": n.id,
            "kind": n.kind,
            "title": n.title,
            "body": n.body,
            "ref_type": n.ref_type,
            "ref_id": n.ref_id,
            "read_at": n.read_at.isoformat() if n.read_at else None,
            "created_at": n.created_at.isoformat(),
        }
        for n in rows
    ]


@app.patch("/notifications/{notification_id}/read")
def mark_notification_read(
    notification_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    n = db.get(PlatformNotification, notification_id)
    if not n or n.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Notifica non trovata")
    n.read_at = datetime.utcnow()
    db.commit()
    return {"status": "ok"}


@app.post("/notifications/read-all")
def mark_all_notifications_read(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    rows = (
        db.query(PlatformNotification)
        .filter(
            PlatformNotification.user_id == current_user.id,
            PlatformNotification.read_at.is_(None),
        )
        .all()
    )
    now = datetime.utcnow()
    for n in rows:
        n.read_at = now
    db.commit()
    return {"status": "ok", "updated": len(rows)}


@app.get("/community/users")
def community_users(
    db: Session = Depends(get_db), _current_user: User = Depends(get_current_user)
):
    now = datetime.utcnow()
    online_user_ids = {
        row[0]
        for row in db.query(AuthToken.user_id)
        .filter(
            AuthToken.token_type == "access",
            AuthToken.revoked.is_(False),
            AuthToken.expires_at > now,
        )
        .distinct()
        .all()
    }
    users = (
        db.query(User)
        .filter(User.is_approved.is_(True))
        .order_by(User.id.desc())
        .limit(200)
        .all()
    )
    return [
        {
            "id": u.id,
            "name": u.name,
            "target_segment": u.target_segment,
            "profile_mode": getattr(u, "profile_mode", None) or "privato",
            "avatar_url": u.avatar_url,
            "company_photo_url": getattr(u, "company_photo_url", None),
            "is_online": u.id in online_user_ids,
        }
        for u in users
    ]


@app.get("/products")
def list_products(db: Session = Depends(get_db)):
    items = db.query(Product).order_by(Product.id.desc()).all()
    return [{"id": p.id, "name": p.name, "price": float(p.price)} for p in items]


@app.post("/admin/products")
def admin_create_product(
    payload: ProductCreate,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    product = Product(name=payload.name.strip(), price=Decimal(str(payload.price)))
    db.add(product)
    db.commit()
    db.refresh(product)
    return {"id": product.id, "name": product.name, "price": float(product.price)}


@app.get("/admin/orders")
def admin_list_orders(db: Session = Depends(get_db), _admin: User = Depends(require_admin)):
    orders = db.query(Order).order_by(Order.id.desc()).limit(200).all()
    return [
        {
            "id": o.id,
            "user_id": o.user_id,
            "product_id": o.product_id,
            "total": float(o.total),
            "status": o.status,
            "created_at": o.created_at.isoformat(),
        }
        for o in orders
    ]


@app.post("/admin/ecommerce/products")
def admin_create_ecommerce_product(
    payload: EcommerceProductCreate,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    item = EcommerceProduct(
        title=payload.title.strip(),
        description=payload.description.strip(),
        showcase_text=payload.showcase_text.strip(),
        category=payload.category.strip() or "general",
        image_url=payload.image_url,
        price=Decimal(str(payload.price)),
        stock=max(payload.stock, 0),
        status="active",
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return {
        "id": item.id,
        "title": item.title,
        "description": item.description,
        "showcase_text": item.showcase_text,
        "category": item.category,
        "image_url": item.image_url,
        "price": float(item.price),
        "stock": item.stock,
        "status": item.status,
    }


@app.patch("/admin/ecommerce/products/{product_id}")
def admin_update_ecommerce_product(
    product_id: int,
    payload: EcommerceProductUpdate,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    item = db.get(EcommerceProduct, product_id)
    if not item:
        raise HTTPException(status_code=404, detail="Prodotto ecommerce non trovato")
    if payload.title is not None:
        item.title = payload.title.strip()
    if payload.description is not None:
        item.description = payload.description.strip()
    if payload.showcase_text is not None:
        item.showcase_text = payload.showcase_text.strip()
    if payload.category is not None:
        item.category = payload.category.strip() or "general"
    if payload.image_url is not None:
        item.image_url = payload.image_url.strip() or None
    if payload.price is not None:
        item.price = Decimal(str(payload.price))
    if payload.stock is not None:
        item.stock = max(payload.stock, 0)
    if payload.status is not None:
        if payload.status not in {"active", "inactive"}:
            raise HTTPException(status_code=400, detail="Status non valido")
        item.status = payload.status
    db.commit()
    db.refresh(item)
    return {"status": "ok", "id": item.id}


@app.delete("/admin/ecommerce/products/{product_id}")
def admin_delete_ecommerce_product(
    product_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    item = db.get(EcommerceProduct, product_id)
    if not item:
        raise HTTPException(status_code=404, detail="Prodotto ecommerce non trovato")
    item.status = "inactive"
    db.commit()
    return {"status": "ok"}


@app.get("/ecommerce/products")
def ecommerce_list_products(
    db: Session = Depends(get_db),
    q: Optional[str] = None,
    category: Optional[str] = None,
):
    feature_enabled_or_503(db, "ecommerce")
    query = db.query(EcommerceProduct).filter(EcommerceProduct.status == "active")
    if q:
        like = f"%{q.strip()}%"
        query = query.filter(
            (EcommerceProduct.title.ilike(like))
            | (EcommerceProduct.description.ilike(like))
            | (EcommerceProduct.showcase_text.ilike(like))
        )
    if category:
        query = query.filter(EcommerceProduct.category == category.strip())
    items = query.order_by(EcommerceProduct.id.desc()).all()
    return [
        {
            "id": i.id,
            "title": i.title,
            "description": i.description,
            "showcase_text": i.showcase_text,
            "category": i.category,
            "image_url": i.image_url,
            "price": float(i.price),
            "stock": i.stock,
        }
        for i in items
    ]


@app.post("/ecommerce/cart/items")
def add_cart_item(
    payload: CartAddIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    feature_enabled_or_503(db, "ecommerce")
    product = db.get(EcommerceProduct, payload.ecommerce_product_id)
    if not product or product.status != "active":
        raise HTTPException(status_code=404, detail="Prodotto ecommerce non trovato")
    qty = max(payload.quantity, 1)
    existing = (
        db.query(CartItem)
        .filter(
            CartItem.user_id == current_user.id,
            CartItem.ecommerce_product_id == product.id,
        )
        .first()
    )
    if existing:
        existing.quantity = min(existing.quantity + qty, product.stock if product.stock > 0 else 9999)
    else:
        db.add(
            CartItem(
                user_id=current_user.id,
                ecommerce_product_id=product.id,
                quantity=min(qty, product.stock if product.stock > 0 else 9999),
            )
        )
    db.commit()
    return {"status": "ok"}


@app.patch("/ecommerce/cart/items/{item_id}")
def update_cart_item(
    item_id: int,
    payload: CartUpdateIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    feature_enabled_or_503(db, "ecommerce")
    item = db.get(CartItem, item_id)
    if not item or item.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Item carrello non trovato")
    if payload.quantity <= 0:
        db.delete(item)
    else:
        max_qty = item.product.stock if item.product.stock > 0 else 9999
        item.quantity = min(payload.quantity, max_qty)
    db.commit()
    return {"status": "ok"}


@app.delete("/ecommerce/cart/items/{item_id}")
def remove_cart_item(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    feature_enabled_or_503(db, "ecommerce")
    item = db.get(CartItem, item_id)
    if not item or item.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Item carrello non trovato")
    db.delete(item)
    db.commit()
    return {"status": "ok"}


@app.get("/ecommerce/cart")
def get_cart(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    feature_enabled_or_503(db, "ecommerce")
    items = db.query(CartItem).filter(CartItem.user_id == current_user.id).all()
    rows = []
    total = Decimal("0.00")
    for item in items:
        line_total = item.product.price * item.quantity
        total += line_total
        rows.append(
            {
                "item_id": item.id,
                "product_id": item.product.id,
                "title": item.product.title,
                "price": float(item.product.price),
                "quantity": item.quantity,
                "line_total": float(line_total),
                "image_url": item.product.image_url,
            }
        )
    return {"items": rows, "total": float(total)}


@app.post("/ecommerce/cart/checkout")
def checkout_cart(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    feature_enabled_or_503(db, "ecommerce")
    feature_enabled_or_503(db, "payments")
    cart_items = db.query(CartItem).filter(CartItem.user_id == current_user.id).all()
    if not cart_items:
        raise HTTPException(status_code=400, detail="Carrello vuoto")

    grand_total = Decimal("0.00")
    for item in cart_items:
        if item.product.status != "active":
            raise HTTPException(status_code=400, detail=f"Prodotto non attivo: {item.product.title}")
        if item.product.stock < item.quantity:
            raise HTTPException(status_code=400, detail=f"Stock insufficiente: {item.product.title}")
        grand_total += item.product.price * item.quantity

    if STRIPE_SECRET_KEY:
        line_items = []
        for item in cart_items:
            line_items.append(
                {
                    "quantity": item.quantity,
                    "price_data": {
                        "currency": "eur",
                        "unit_amount": int(item.product.price * 100),
                        "product_data": {"name": item.product.title},
                    },
                }
            )
        session = stripe.checkout.Session.create(
            mode="payment",
            success_url="https://example.com/success",
            cancel_url="https://example.com/cancel",
            metadata={"user_id": str(current_user.id), "cart_checkout": "true"},
            line_items=line_items,
        )
        return {"status": "redirect", "checkout_url": session.url, "total": float(grand_total)}

    # Fallback locale: simula pagamento completato e scala stock.
    for item in cart_items:
        item.product.stock -= item.quantity
    db.query(CartItem).filter(CartItem.user_id == current_user.id).delete()
    db.commit()
    return {"status": "paid", "total": float(grand_total), "message": "Checkout locale completato"}


@app.post("/orders")
def create_order(
    payload: OrderCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    product = db.get(Product, payload.product_id)
    if not product:
        raise HTTPException(status_code=404, detail="Prodotto non trovato")

    coins_to_spend = max(payload.coins_to_spend, 0)
    if coins_to_spend > current_user.coins:
        raise HTTPException(status_code=400, detail="Monete insufficienti")

    discount = Decimal(coins_to_spend) * Decimal("0.10")
    total = product.price - discount
    if total < Decimal("0.00"):
        total = Decimal("0.00")

    order = Order(
        user_id=current_user.id,
        product_id=product.id,
        total=total,
        status="created",
    )
    db.add(order)

    if coins_to_spend > 0:
        current_user.coins -= coins_to_spend
        db.add(
            CoinTransaction(
                user_id=current_user.id, amount=-coins_to_spend, reason="order_discount"
            )
        )

    earned = int(float(product.price) // 10)
    if earned > 0:
        current_user.coins += earned
        db.add(CoinTransaction(user_id=current_user.id, amount=earned, reason="order_reward"))

    db.commit()
    db.refresh(order)

    return {
        "order_id": order.id,
        "product_id": order.product_id,
        "total": float(order.total),
        "coins_spent": coins_to_spend,
        "coins_earned": earned,
    }


@app.post("/payments/checkout-session")
def create_checkout_session(
    payload: OrderCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    feature_enabled_or_503(db, "payments")
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Stripe non configurato")
    product = db.get(Product, payload.product_id)
    if not product:
        raise HTTPException(status_code=404, detail="Prodotto non trovato")

    order = Order(
        user_id=current_user.id,
        product_id=product.id,
        total=product.price,
        status="pending_payment",
    )
    db.add(order)
    db.commit()
    db.refresh(order)

    session = stripe.checkout.Session.create(
        mode="payment",
        success_url="https://example.com/success",
        cancel_url="https://example.com/cancel",
        metadata={"order_id": str(order.id), "user_id": str(current_user.id)},
        line_items=[
            {
                "quantity": 1,
                "price_data": {
                    "currency": "eur",
                    "unit_amount": int(product.price * 100),
                    "product_data": {"name": product.name},
                },
            }
        ],
    )
    order.stripe_session_id = session.id
    db.commit()
    return {"checkout_url": session.url, "order_id": order.id}


@app.get("/account/my-products")
def my_products(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    rows = (
        db.query(UserProduct)
        .filter(UserProduct.owner_user_id == current_user.id)
        .order_by(UserProduct.id.desc())
        .all()
    )
    return [
        {
            "id": x.id,
            "title": x.title,
            "description": x.description,
            "price": float(x.price),
            "status": x.status,
            "created_at": x.created_at.isoformat(),
        }
        for x in rows
    ]


@app.post("/account/my-products")
def create_my_product(
    payload: UserProductIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    status = payload.status if payload.status in {"draft", "published"} else "draft"
    item = UserProduct(
        owner_user_id=current_user.id,
        title=payload.title.strip(),
        description=payload.description.strip(),
        price=Decimal(str(max(payload.price, 0))),
        status=status,
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    if status == "published":
        _notify_users_except(
            db,
            current_user.id,
            "product_published",
            "Nuovo prodotto in vetrina",
            f"{current_user.name} ha pubblicato: {item.title}",
            "user_product",
            item.id,
        )
        db.commit()
    return {"id": item.id, "status": "created"}


@app.patch("/account/my-products/{product_id}")
def update_my_product(
    product_id: int,
    payload: UserProductIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    item = db.get(UserProduct, product_id)
    if not item or item.owner_user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Prodotto utente non trovato")
    old_status = item.status
    item.title = payload.title.strip()
    item.description = payload.description.strip()
    item.price = Decimal(str(max(payload.price, 0)))
    item.status = payload.status if payload.status in {"draft", "published"} else "draft"
    db.commit()
    if old_status != "published" and item.status == "published":
        _notify_users_except(
            db,
            current_user.id,
            "product_published",
            "Nuovo prodotto in vetrina",
            f"{current_user.name} ha pubblicato: {item.title}",
            "user_product",
            item.id,
        )
        db.commit()
    return {"status": "ok"}


@app.delete("/account/my-products/{product_id}")
def delete_my_product(
    product_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    item = db.get(UserProduct, product_id)
    if not item or item.owner_user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Prodotto utente non trovato")
    db.delete(item)
    db.commit()
    return {"status": "ok"}


@app.get("/account/my-courses")
def my_courses(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    created = (
        db.query(UserCourse)
        .filter(UserCourse.owner_user_id == current_user.id)
        .order_by(UserCourse.id.desc())
        .all()
    )
    enrolled_rows = (
        db.query(CourseEnrollment)
        .filter(CourseEnrollment.user_id == current_user.id)
        .order_by(CourseEnrollment.id.desc())
        .all()
    )
    return {
        "created": [
            {
                "id": c.id,
                "title": c.title,
                "description": c.description,
                "price": float(c.price),
                "status": c.status,
            }
            for c in created
        ],
        "enrolled": [
            {
                "enrollment_id": e.id,
                "course_id": e.course.id,
                "title": e.course.title,
                "owner_user_id": e.course.owner_user_id,
            }
            for e in enrolled_rows
        ],
    }


@app.post("/account/my-courses")
def create_my_course(
    payload: UserCourseIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    status = payload.status if payload.status in {"draft", "published"} else "draft"
    item = UserCourse(
        owner_user_id=current_user.id,
        title=payload.title.strip(),
        description=payload.description.strip(),
        price=Decimal(str(max(payload.price, 0))),
        status=status,
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return {"id": item.id, "status": "created"}


@app.post("/courses/{course_id}/enroll")
def enroll_course(
    course_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    course = db.get(UserCourse, course_id)
    if not course or course.status != "published":
        raise HTTPException(status_code=404, detail="Corso non trovato")
    existing = (
        db.query(CourseEnrollment)
        .filter(CourseEnrollment.user_id == current_user.id, CourseEnrollment.course_id == course_id)
        .first()
    )
    if existing:
        raise HTTPException(status_code=409, detail="Gia iscritto al corso")
    db.add(CourseEnrollment(user_id=current_user.id, course_id=course_id))
    db.commit()
    return {"status": "ok"}


@app.get("/courses/marketplace")
def courses_marketplace(db: Session = Depends(get_db)):
    rows = db.query(UserCourse).filter(UserCourse.status == "published").all()
    return [
        {
            "id": c.id,
            "title": c.title,
            "description": c.description,
            "price": float(c.price),
            "owner_user_id": c.owner_user_id,
        }
        for c in rows
    ]


@app.get("/account/workspaces")
def my_workspaces(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    rows = (
        db.query(Workspace)
        .filter(Workspace.owner_user_id == current_user.id)
        .order_by(Workspace.id.desc())
        .all()
    )
    return [
        {"id": w.id, "name": w.name, "description": w.description, "created_at": w.created_at.isoformat()}
        for w in rows
    ]


@app.post("/account/workspaces")
def create_workspace(
    payload: WorkspaceIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    w = Workspace(
        owner_user_id=current_user.id,
        name=payload.name.strip(),
        description=payload.description.strip(),
    )
    db.add(w)
    db.commit()
    db.refresh(w)
    return {"id": w.id, "status": "created"}


@app.delete("/account/workspaces/{workspace_id}")
def delete_workspace(
    workspace_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    w = db.get(Workspace, workspace_id)
    if not w or w.owner_user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Workspace non trovato")
    db.delete(w)
    db.commit()
    return {"status": "ok"}


def _workspace_owned(db: Session, workspace_id: int, user_id: int) -> Workspace:
    w = db.get(Workspace, workspace_id)
    if not w or w.owner_user_id != user_id:
        raise HTTPException(status_code=404, detail="Workspace non trovato")
    return w


@app.get("/account/workspaces/{workspace_id}/notes")
def list_workspace_notes(
    workspace_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _workspace_owned(db, workspace_id, current_user.id)
    rows = (
        db.query(WorkspaceNote)
        .filter(
            WorkspaceNote.workspace_id == workspace_id,
            WorkspaceNote.owner_user_id == current_user.id,
        )
        .order_by(WorkspaceNote.note_at.desc(), WorkspaceNote.id.desc())
        .all()
    )
    return [
        {
            "id": n.id,
            "workspace_id": n.workspace_id,
            "title": n.title,
            "content": n.content,
            "note_at": n.note_at.isoformat(),
            "reminder_at": n.reminder_at.isoformat() if n.reminder_at else None,
            "is_done": n.is_done,
            "created_at": n.created_at.isoformat(),
        }
        for n in rows
    ]


@app.post("/account/workspaces/{workspace_id}/notes")
def create_workspace_note(
    workspace_id: int,
    payload: WorkspaceNoteIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _workspace_owned(db, workspace_id, current_user.id)
    content = (payload.content or "").strip()
    if len(content) < 1:
        raise HTTPException(status_code=400, detail="Contenuto nota obbligatorio")
    note_at = payload.note_at or datetime.utcnow()
    n = WorkspaceNote(
        workspace_id=workspace_id,
        owner_user_id=current_user.id,
        title=(payload.title or "").strip()[:200],
        content=content,
        note_at=note_at,
        reminder_at=payload.reminder_at,
        is_done=False,
    )
    db.add(n)
    db.commit()
    db.refresh(n)
    return {"id": n.id, "status": "created"}


@app.patch("/account/workspaces/{workspace_id}/notes/{note_id}")
def update_workspace_note(
    workspace_id: int,
    note_id: int,
    payload: WorkspaceNoteUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _workspace_owned(db, workspace_id, current_user.id)
    n = db.get(WorkspaceNote, note_id)
    if not n or n.workspace_id != workspace_id or n.owner_user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Nota non trovata")
    if payload.title is not None:
        n.title = payload.title.strip()[:200]
    if payload.content is not None:
        n.content = payload.content.strip()
    if payload.note_at is not None:
        n.note_at = payload.note_at
    if payload.reminder_at is not None:
        n.reminder_at = payload.reminder_at
    if payload.is_done is not None:
        n.is_done = payload.is_done
    db.commit()
    return {"status": "ok"}


@app.delete("/account/workspaces/{workspace_id}/notes/{note_id}")
def delete_workspace_note(
    workspace_id: int,
    note_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _workspace_owned(db, workspace_id, current_user.id)
    n = db.get(WorkspaceNote, note_id)
    if not n or n.workspace_id != workspace_id or n.owner_user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Nota non trovata")
    db.delete(n)
    db.commit()
    return {"status": "ok"}


@app.get("/account/workspaces/{workspace_id}/social-posts")
def list_workspace_social_posts(
    workspace_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _workspace_owned(db, workspace_id, current_user.id)
    rows = (
        db.query(WorkspacePost)
        .filter(WorkspacePost.workspace_id == workspace_id)
        .order_by(WorkspacePost.id.desc())
        .limit(100)
        .all()
    )
    out = []
    for p in rows:
        u = db.get(User, p.owner_user_id)
        out.append(
            {
                "id": p.id,
                "content": p.content,
                "owner_user_id": p.owner_user_id,
                "author_name": u.name if u else "?",
                "created_at": p.created_at.isoformat(),
            }
        )
    return out


@app.post("/account/workspaces/{workspace_id}/social-posts")
def create_workspace_social_post(
    workspace_id: int,
    payload: WorkspacePostIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _workspace_owned(db, workspace_id, current_user.id)
    content = payload.content.strip()
    if len(content) < 3:
        raise HTTPException(status_code=400, detail="Contenuto troppo corto")
    post = WorkspacePost(
        workspace_id=workspace_id,
        owner_user_id=current_user.id,
        content=content,
    )
    db.add(post)
    db.commit()
    db.refresh(post)
    return {"id": post.id, "status": "created"}


@app.delete("/account/workspaces/{workspace_id}/social-posts/{post_id}")
def delete_workspace_social_post(
    workspace_id: int,
    post_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _workspace_owned(db, workspace_id, current_user.id)
    post = db.get(WorkspacePost, post_id)
    if not post or post.workspace_id != workspace_id or post.owner_user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Post non trovato")
    db.delete(post)
    db.commit()
    return {"status": "ok"}


@app.get("/account/calendar/reminders")
def account_calendar_reminders(
    start: Optional[str] = Query(None, description="ISO8601 inizio intervallo"),
    end: Optional[str] = Query(None, description="ISO8601 fine intervallo"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    q = (
        db.query(WorkspaceNote)
        .filter(
            WorkspaceNote.owner_user_id == current_user.id,
            WorkspaceNote.reminder_at.isnot(None),
        )
    )
    if start:
        try:
            start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(status_code=400, detail="start non valido (usa ISO8601)")
        q = q.filter(WorkspaceNote.reminder_at >= start_dt)
    if end:
        try:
            end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(status_code=400, detail="end non valido (usa ISO8601)")
        q = q.filter(WorkspaceNote.reminder_at <= end_dt)
    rows = q.order_by(WorkspaceNote.reminder_at.asc()).limit(500).all()
    out = []
    for n in rows:
        w = db.get(Workspace, n.workspace_id)
        out.append(
            {
                "id": n.id,
                "workspace_id": n.workspace_id,
                "workspace_name": w.name if w else "",
                "title": n.title,
                "content": n.content,
                "note_at": n.note_at.isoformat(),
                "reminder_at": n.reminder_at.isoformat() if n.reminder_at else None,
                "is_done": n.is_done,
            }
        )
    return out


@app.post("/business/join")
def join_business_account(
    payload: BusinessJoinIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    existing = db.query(BusinessProfile).filter(BusinessProfile.user_id == current_user.id).first()
    if existing:
        raise HTTPException(status_code=409, detail="Profilo business gia attivo")

    sponsor = None
    if payload.sponsor_user_id:
        sponsor = db.get(User, payload.sponsor_user_id)
        if not sponsor:
            raise HTTPException(status_code=404, detail="Sponsor non trovato")

    profile = BusinessProfile(
        user_id=current_user.id,
        level=resolve_business_level(10),
        points=10,
        direct_referrals=0,
        sponsor_user_id=payload.sponsor_user_id,
    )
    db.add(profile)

    if sponsor:
        sponsor_profile = db.query(BusinessProfile).filter(BusinessProfile.user_id == sponsor.id).first()
        if sponsor_profile:
            sponsor_profile.direct_referrals += 1
            sponsor_profile.points += 15
            sponsor_profile.level = resolve_business_level(sponsor_profile.points)

    db.commit()
    return {"status": "ok", "message": "Account business attivato"}


@app.get("/business/me")
def business_me(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    profile = db.query(BusinessProfile).filter(BusinessProfile.user_id == current_user.id).first()
    if not profile:
        return {"active": False}
    level_labels = {
        "starter_seller": "Starter Seller",
        "smart_vendor": "Smart Vendor",
        "growth_manager": "Growth Manager",
        "business_manager": "Business Manager",
        "area_director": "Area Director",
        "executive_partner": "Executive Partner",
    }
    return {
        "active": True,
        "level": profile.level,
        "level_label": level_labels.get(profile.level, profile.level),
        "points": profile.points,
        "direct_referrals": profile.direct_referrals,
        "sponsor_user_id": profile.sponsor_user_id,
    }


@app.get("/business/pyramid")
def business_pyramid(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    profile = db.query(BusinessProfile).filter(BusinessProfile.user_id == current_user.id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Profilo business non attivo")

    directs = db.query(BusinessProfile).filter(BusinessProfile.sponsor_user_id == current_user.id).all()
    second_level_ids = [d.user_id for d in directs]
    seconds = []
    if second_level_ids:
        seconds = (
            db.query(BusinessProfile)
            .filter(BusinessProfile.sponsor_user_id.in_(second_level_ids))
            .all()
        )
    return {
        "me": {
            "user_id": current_user.id,
            "level": profile.level,
            "points": profile.points,
            "direct_referrals": profile.direct_referrals,
        },
        "direct_team": [
            {"user_id": d.user_id, "level": d.level, "points": d.points, "direct_referrals": d.direct_referrals}
            for d in directs
        ],
        "second_line_count": len(seconds),
    }


@app.post("/business/ads")
def create_business_ad(
    payload: BusinessAdIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    profile = db.query(BusinessProfile).filter(BusinessProfile.user_id == current_user.id).first()
    if not profile:
        raise HTTPException(status_code=403, detail="Attiva prima l'account business")

    item = BusinessAd(
        owner_user_id=current_user.id,
        title=payload.title.strip(),
        description=payload.description.strip(),
        channel=payload.channel.strip() or "social",
        budget=Decimal(str(max(payload.budget, 0))),
        status=payload.status if payload.status in {"draft", "active", "paused"} else "draft",
    )
    db.add(item)
    profile.points += 5
    profile.level = resolve_business_level(profile.points)
    db.commit()
    db.refresh(item)
    return {"id": item.id, "status": "created"}


@app.get("/business/ads")
def list_business_ads(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rows = (
        db.query(BusinessAd)
        .filter(BusinessAd.owner_user_id == current_user.id)
        .order_by(BusinessAd.id.desc())
        .all()
    )
    return [
        {
            "id": x.id,
            "title": x.title,
            "description": x.description,
            "channel": x.channel,
            "budget": float(x.budget),
            "status": x.status,
            "created_at": x.created_at.isoformat(),
        }
        for x in rows
    ]


@app.post("/target/offers")
def create_target_offer(
    payload: TargetOfferIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    item = TargetOffer(
        seller_user_id=current_user.id,
        seller_target=current_user.target_segment,
        title=payload.title.strip(),
        description=payload.description.strip(),
        coin_price=max(payload.coin_price, 1),
        quantity_available=max(payload.quantity_available, 1),
        status="active",
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return {"id": item.id, "status": "created"}


@app.get("/target/offers")
def list_target_offers(db: Session = Depends(get_db)):
    rows = (
        db.query(TargetOffer)
        .filter(TargetOffer.status == "active", TargetOffer.quantity_available > 0)
        .order_by(TargetOffer.id.desc())
        .all()
    )
    return [
        {
            "id": o.id,
            "seller_user_id": o.seller_user_id,
            "seller_target": o.seller_target,
            "title": o.title,
            "description": o.description,
            "coin_price": o.coin_price,
            "quantity_available": o.quantity_available,
        }
        for o in rows
    ]


@app.post("/target/offers/{offer_id}/redeem")
def redeem_target_offer(
    offer_id: int,
    payload: OfferRedeemIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    offer = db.get(TargetOffer, offer_id)
    if not offer or offer.status != "active":
        raise HTTPException(status_code=404, detail="Offerta non trovata")
    if offer.seller_user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Non puoi riscattare la tua offerta")

    qty = max(payload.quantity, 1)
    if offer.quantity_available < qty:
        raise HTTPException(status_code=400, detail="Quantita non disponibile")

    total_coins = offer.coin_price * qty
    if current_user.coins < total_coins:
        raise HTTPException(status_code=400, detail="Monete insufficienti")

    seller = db.get(User, offer.seller_user_id)
    if not seller:
        raise HTTPException(status_code=404, detail="Venditore non trovato")

    current_user.coins -= total_coins
    seller.coins += total_coins
    offer.quantity_available -= qty
    if offer.quantity_available == 0:
        offer.status = "inactive"

    db.add(
        CoinTransaction(
            user_id=current_user.id,
            amount=-total_coins,
            reason=f"redeem_offer_{offer.id}",
        )
    )
    db.add(
        CoinTransaction(
            user_id=seller.id,
            amount=total_coins,
            reason=f"offer_sale_{offer.id}",
        )
    )
    db.add(
        OfferRedemption(
            offer_id=offer.id,
            buyer_user_id=current_user.id,
            seller_user_id=seller.id,
            quantity=qty,
            total_coins=total_coins,
        )
    )

    db.commit()
    return {
        "status": "ok",
        "offer_id": offer.id,
        "quantity": qty,
        "coins_spent": total_coins,
        "buyer_remaining_coins": current_user.coins,
        "seller_target": offer.seller_target,
    }


@app.get("/target/redemptions/me")
def my_target_redemptions(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rows = (
        db.query(OfferRedemption)
        .filter(OfferRedemption.buyer_user_id == current_user.id)
        .order_by(OfferRedemption.id.desc())
        .limit(100)
        .all()
    )
    return [
        {
            "id": r.id,
            "offer_id": r.offer_id,
            "seller_user_id": r.seller_user_id,
            "quantity": r.quantity,
            "total_coins": r.total_coins,
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]


@app.post("/payments/webhook/stripe")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)):
    feature_enabled_or_503(db, "payments")
    if not STRIPE_WEBHOOK_SECRET:
        token = request.headers.get("x-webhook-token")
        if token != WEBHOOK_AUTH_TOKEN:
            raise HTTPException(status_code=401, detail="Webhook non autorizzato")
        event = await request.json()
    else:
        sig_header = request.headers.get("stripe-signature")
        payload = await request.body()
        try:
            event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Webhook non valido: {exc}") from exc

    event_type = event.get("type")
    data_obj = event.get("data", {}).get("object", {})

    if event_type == "checkout.session.completed":
        order_id = int(data_obj.get("metadata", {}).get("order_id", 0))
        payment_intent = data_obj.get("payment_intent")
        order = db.get(Order, order_id)
        if order:
            order.status = "paid"
            order.stripe_payment_intent = payment_intent
            db.commit()

    return {"received": True}


@app.get("/admin/api-controls")
def admin_list_api_controls(
    db: Session = Depends(get_db), _admin: User = Depends(require_admin)
):
    items = db.query(FeatureToggle).order_by(FeatureToggle.feature_key.asc()).all()
    return [
        {"feature_key": x.feature_key, "enabled": x.enabled, "updated_at": x.updated_at.isoformat()}
        for x in items
    ]


@app.patch("/admin/api-controls/{feature_key}")
def admin_set_api_control(
    feature_key: str,
    payload: FeatureToggleUpdate,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    item = db.query(FeatureToggle).filter(FeatureToggle.feature_key == feature_key).first()
    if not item:
        raise HTTPException(status_code=404, detail="Feature non trovata")
    item.enabled = payload.enabled
    item.updated_at = datetime.utcnow()
    db.commit()
    return {"status": "ok", "feature_key": item.feature_key, "enabled": item.enabled}
