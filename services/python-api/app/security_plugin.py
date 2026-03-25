import secrets
from datetime import datetime, timedelta

import pyotp


def generate_numeric_otp(length: int = 6) -> str:
    max_value = 10**length
    return f"{secrets.randbelow(max_value):0{length}d}"


def otp_expiration(minutes: int = 10) -> datetime:
    return datetime.utcnow() + timedelta(minutes=minutes)


def verify_google_totp(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def build_google_totp_setup(email: str, issuer: str = "ClubBusinessIA") -> dict:
    secret = pyotp.random_base32()
    uri = pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)
    return {"secret": secret, "otpauth_uri": uri}


def password_security_check(password: str) -> tuple[bool, str]:
    if len(password) < 8:
        return False, "Password troppo corta (minimo 8 caratteri)"
    if password.lower() == password or password.upper() == password:
        return False, "Password debole: usa maiuscole e minuscole"
    if not any(ch.isdigit() for ch in password):
        return False, "Password debole: inserisci almeno un numero"
    return True, "ok"
