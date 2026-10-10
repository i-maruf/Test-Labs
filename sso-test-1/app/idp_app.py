import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode
from uuid import uuid4

import jwt
from dotenv import load_dotenv
from flask import Flask, abort, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

from idp_keys import KID, jwks, private_key_pem
from models import IdpAccount, IdpAuthCode, make_session_factory

load_dotenv()

app = Flask(__name__, template_folder="idp_templates", static_folder="static")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
app.secret_key = os.environ.get("APP_SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_NAME="idp_session",
)

ISSUER = os.environ.get("IDP_ISSUER", "http://localhost:8080/oidc").rstrip("/")
CLIENT_ID = os.environ.get("IDP_CLIENT_ID", "sso-test-1-web")
CLIENT_SECRET = os.environ.get("IDP_CLIENT_SECRET", "sso-test-1-web-secret")
ALLOWED_REDIRECTS = {
    uri.strip()
    for uri in os.environ.get(
        "IDP_REDIRECT_URIS",
        "http://localhost:8080/auth/callback,http://127.0.0.1:8080/auth/callback",
    ).split(",")
    if uri.strip()
}
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://sso:sso@db:5432/ssodb")
SessionLocal = make_session_factory(DATABASE_URL)


@app.get("/oidc/.well-known/openid-configuration")
def discovery():
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "jwks_uri": f"{ISSUER}/jwks",
        "end_session_endpoint": f"{ISSUER}/logout",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["S256"],
    }


@app.get("/oidc/jwks")
def jwks_endpoint():
    return jwks()


@app.route("/oidc/authorize", methods=["GET", "POST"])
def authorize():
    params = request.values
    client_id = params.get("client_id")
    redirect_uri = params.get("redirect_uri")
    state = params.get("state")
    nonce = params.get("nonce")
    prompt = params.get("prompt") or "login"
    code_challenge = params.get("code_challenge")
    if client_id != CLIENT_ID or redirect_uri not in ALLOWED_REDIRECTS:
        abort(400, "invalid_client_or_redirect")

    session["auth_request"] = {
        "redirect_uri": redirect_uri,
        "state": state,
        "nonce": nonce,
        "prompt": prompt,
        "code_challenge": code_challenge,
        "client_id": client_id,
    }

    account = _current_account()
    if request.method == "GET" and account and prompt not in {"login", "create"}:
        return _issue_code_and_redirect(account)

    mode = "signup" if prompt == "create" else "signin"

    error = None
    if request.method == "POST":
        mode = request.form.get("mode", "signin")
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        given_name = (request.form.get("given_name") or "").strip()
        family_name = (request.form.get("family_name") or "").strip()
        db = SessionLocal()
        try:
            if mode == "signup":
                if not email or not password or len(password) < 8:
                    error = "Email and a password of at least 8 characters are required."
                elif db.query(IdpAccount).filter_by(email=email).one_or_none():
                    error = "An account with that email already exists. Sign in instead."
                else:
                    account = IdpAccount(
                        oid=str(uuid4()),
                        email=email,
                        given_name=given_name or None,
                        family_name=family_name or None,
                        name=" ".join(part for part in (given_name, family_name) if part) or email,
                        password_hash=generate_password_hash(password),
                    )
                    db.add(account)
                    db.commit()
                    db.refresh(account)
                    session["idp_user_id"] = account.id
                    return _issue_code_and_redirect(account)
            else:
                account = db.query(IdpAccount).filter_by(email=email).one_or_none()
                if not account or not check_password_hash(account.password_hash, password):
                    error = "Incorrect email or password."
                else:
                    session["idp_user_id"] = account.id
                    return _issue_code_and_redirect(account)
        finally:
            db.close()

    query = urlencode({k: v for k, v in request.args.items(multi=True) if k != "prompt"})
    return render_template("idp_auth.html", mode=mode, error=error, prompt=prompt, auth_query=query)


@app.post("/oidc/token")
def token():
    data = request.form
    if data.get("grant_type") != "authorization_code":
        return {"error": "unsupported_grant_type"}, 400
    client_id, client_secret = _client_auth(data)
    if client_id != CLIENT_ID or client_secret != CLIENT_SECRET:
        return {"error": "invalid_client"}, 401

    code = data.get("code")
    redirect_uri = data.get("redirect_uri")
    code_verifier = data.get("code_verifier")
    db = SessionLocal()
    try:
        record = db.get(IdpAuthCode, code)
        now = datetime.now(timezone.utc)
        if not record or record.expires_at <= now or record.redirect_uri != redirect_uri:
            return {"error": "invalid_grant"}, 400
        if record.code_challenge:
            digest = hashlib.sha256((code_verifier or "").encode("ascii")).digest()
            import base64

            challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
            if challenge != record.code_challenge:
                return {"error": "invalid_grant"}, 400
        account = db.get(IdpAccount, record.account_id)
        db.delete(record)
        db.commit()
        if not account:
            return {"error": "invalid_grant"}, 400
        id_token = _id_token(account, record.nonce)
        return {
            "access_token": secrets.token_urlsafe(32),
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": id_token,
            "scope": "openid profile email",
        }
    finally:
        db.close()


@app.get("/oidc/logout")
def logout():
    session.clear()
    return redirect(request.args.get("post_logout_redirect_uri") or "http://localhost:8080/")


@app.get("/health")
def health():
    return {"status": "ok"}


def _client_auth(data):
    if request.authorization:
        return request.authorization.username, request.authorization.password
    return data.get("client_id"), data.get("client_secret")


def _current_account():
    user_id = session.get("idp_user_id")
    if not user_id:
        return None
    db = SessionLocal()
    try:
        return db.get(IdpAccount, user_id)
    finally:
        db.close()


def _issue_code_and_redirect(account: IdpAccount):
    auth_request = session.get("auth_request") or {}
    code = secrets.token_urlsafe(32)
    db = SessionLocal()
    try:
        db.add(
            IdpAuthCode(
                code=code,
                account_id=account.id,
                client_id=auth_request.get("client_id") or CLIENT_ID,
                redirect_uri=auth_request["redirect_uri"],
                nonce=auth_request.get("nonce"),
                code_challenge=auth_request.get("code_challenge"),
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            )
        )
        db.commit()
    finally:
        db.close()
    query = {"code": code}
    if auth_request.get("state"):
        query["state"] = auth_request["state"]
    return redirect(f"{auth_request['redirect_uri']}?{urlencode(query)}")


def _id_token(account: IdpAccount, nonce: str | None) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "iss": ISSUER,
        "sub": account.oid,
        "aud": CLIENT_ID,
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "iat": int(now.timestamp()),
        "oid": account.oid,
        "tid": "local-lab",
        "preferred_username": account.email,
        "email": account.email,
        "name": account.name,
        "given_name": account.given_name,
        "family_name": account.family_name,
    }
    if nonce:
        payload["nonce"] = nonce
    return jwt.encode(payload, private_key_pem(), algorithm="RS256", headers={"kid": KID})
