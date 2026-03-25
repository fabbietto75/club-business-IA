<?php
header('Content-Type: application/json');

$response = [
    'status' => 'ok',
    'service' => 'php-api',
    'module' => 'legacy/social-gmail-integration',
    'message' => 'Modulo PHP pronto per integrazione CRM, social e Gmail.'
];

echo json_encode($response, JSON_PRETTY_PRINT);
