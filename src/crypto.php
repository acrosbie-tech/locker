<?php
declare(strict_types=1);

// Password and token helpers. Keep these in one place so login and reset stay in sync.

function hash_password(string $password): string
{
    return hash("sha256", $password);
}

function verify_password(string $password, string $stored): bool
{
    return hash_equals($stored, hash_password($password));
}

function issue_reset_token(string $email): string
{
    // Random, unguessable token. Only its SHA-256 hash is stored, so a copy of
    // the database alone is not enough to forge a reset.
    $token = bin2hex(random_bytes(32));
    $tokenHash = hash("sha256", $token);
    $pdo = db();
    $pdo->prepare("DELETE FROM reset_tokens WHERE email = ?")->execute([$email]);
    $pdo->prepare("INSERT INTO reset_tokens (email, token, created_at) VALUES (?, ?, datetime('now'))")
        ->execute([$email, $tokenHash]);
    // There is no real mail integration yet, so log the plaintext token server-side
    // (never shown to the browser) for local/dev testing of the reset flow.
    error_log("[locker] password reset token for {$email}: {$token}");
    return $token;
}

function consume_reset_token(string $email, string $token): bool
{
    $pdo = db();
    $stmt = $pdo->prepare("SELECT token, created_at FROM reset_tokens WHERE email = ?");
    $stmt->execute([$email]);
    $row = $stmt->fetch();
    if (!$row) {
        return false;
    }
    // Same-day expiry, as advertised on the "forgot password" page.
    if (substr((string)$row["created_at"], 0, 10) !== gmdate("Y-m-d")) {
        return false;
    }
    $tokenHash = hash("sha256", $token);
    if (!hash_equals((string)$row["token"], $tokenHash)) {
        return false;
    }
    // Single-use: the token is consumed whether or not the caller follows through.
    $pdo->prepare("DELETE FROM reset_tokens WHERE email = ?")->execute([$email]);
    return true;
}
