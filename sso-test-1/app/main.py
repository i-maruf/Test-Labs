import base64
import hashlib
import os
import secrets
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import urlencode

import jwt
import msal
import requests
from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from jwt import PyJWKClient
from werkzeug.middleware.proxy_fix import ProxyFix

from models import User, make_session_factory

load_dotenv()

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
app.secret_key = os.environ.get("APP_SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true",
)

CLIENT_ID = os.environ.get("MICROSOFT_CLIENT_ID", "").strip()
CLIENT_SECRET = os.environ.get("MICROSOFT_CLIENT_SECRET", "").strip()
TENANT_ID = os.environ.get("MICROSOFT_TENANT_ID", "common").strip() or "common"
PROVIDER = os.environ.get("OIDC_PROVIDER", "local").strip().lower()
REDIRECT_URI = os.environ.get("REDIRECT_URI", "http://localhost:8080/auth/callback").strip()
SCOPES = ["openid", "profile", "email", "User.Read"]
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
GRAPH_ME = "https://graph.microsoft.com/v1.0/me"
OIDC_ISSUER = os.environ.get("OIDC_ISSUER", "http://localhost:8080/oidc").rstrip("/")
OIDC_ISSUER_INTERNAL = os.environ.get("OIDC_ISSUER_INTERNAL", OIDC_ISSUER).rstrip("/")

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://sso:sso@db:5432/ssodb",
)

SessionLocal = make_session_factory(DATABASE_URL)


def configured() -> bool:
    return bool(CLIENT_ID and CLIENT_SECRET)


def uses_microsoft() -> bool:
    return PROVIDER == "microsoft"


def msal_app() -> msal.ConfidentialClientApplication:
    return msal.ConfidentialClientApplication(
        CLIENT_ID,
        authority=AUTHORITY,
        client_credential=CLIENT_SECRET,
    )


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("index"))
        return view(*args, **kwargs)

    return wrapped


@app.get("/")
def index():
    if session.get("user"):
        return redirect(url_for("dashboard"))
    return render_template(
        "index.html",
        configured=configured(),
        tenant=TENANT_ID if uses_microsoft() else "local-lab",
        redirect_uri=REDIRECT_URI,
        client_id_set=bool(CLIENT_ID),
        client_secret_set=bool(CLIENT_SECRET),
        provider=PROVIDER,
        uses_microsoft=uses_microsoft(),
    )


@app.get("/auth/start/<flow>")
def auth_start(flow: str):
    if flow not in {"signin", "signup"}:
        abort(404)
    if not configured():
        flash("SSO client credentials are not configured.", "error")
        return redirect(url_for("index"))

    session["intended_flow"] = flow
    prompt = "create" if flow == "signup" else "login"

    if uses_microsoft():
        auth_flow = msal_app().initiate_auth_code_flow(
            SCOPES,
            redirect_uri=REDIRECT_URI,
            prompt=prompt,
        )
        session["auth_flow"] = auth_flow
        return redirect(auth_flow["auth_uri"])

    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
    session["oidc_flow"] = {
        "state": state,
        "nonce": nonce,
        "code_verifier": verifier,
    }
    query = urlencode(
        {
            "client_id": CLIENT_ID,
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "scope": "openid profile email",
            "state": state,
            "nonce": nonce,
            "prompt": prompt,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    return redirect(f"{OIDC_ISSUER}/authorize?{query}")


@app.get("/auth/callback")
def auth_callback():
    if request.args.get("error"):
        description = request.args.get("error_description") or request.args.get("error")
        flash(f"Identity provider returned an error: {description}", "error")
        return redirect(url_for("index"))

    if uses_microsoft():
        claims = _microsoft_claims()
        if claims is None:
            return redirect(url_for("index"))
        graph_profile = claims.pop("_graph", {})
    else:
        claims = _local_claims()
        if claims is None:
            return redirect(url_for("index"))
        graph_profile = {}

    oid = claims.get("oid") or claims.get("sub")
    if not oid:
        flash("The identity provider did not return a user identifier.", "error")
        return redirect(url_for("index"))

    email = (
        claims.get("preferred_username")
        or claims.get("email")
        or graph_profile.get("mail")
        or graph_profile.get("userPrincipalName")
    )
    name = claims.get("name") or graph_profile.get("displayName")
    given_name = claims.get("given_name") or graph_profile.get("givenName")
    family_name = claims.get("family_name") or graph_profile.get("surname")
    tenant_id = claims.get("tid")
    intended_flow = session.pop("intended_flow", "signin")

    db = SessionLocal()
    try:
        user = db.query(User).filter_by(oid=oid).one_or_none()
        now = datetime.now(timezone.utc)
        is_new = user is None
        if is_new:
            user = User(
                oid=oid,
                email=email,
                name=name,
                given_name=given_name,
                family_name=family_name,
                tenant_id=tenant_id,
                account_type=_account_type(claims),
                last_flow="signup",
                created_at=now,
                last_login_at=now,
            )
            db.add(user)
        else:
            user.email = email or user.email
            user.name = name or user.name
            user.given_name = given_name or user.given_name
            user.family_name = family_name or user.family_name
            user.tenant_id = tenant_id or user.tenant_id
            user.account_type = _account_type(claims)
            user.last_flow = intended_flow
            user.last_login_at = now
        db.commit()
        db.refresh(user)
        session["user"] = {
            "id": user.id,
            "oid": user.oid,
            "email": user.email,
            "name": user.name,
            "given_name": user.given_name,
            "family_name": user.family_name,
            "tenant_id": user.tenant_id,
            "account_type": user.account_type,
            "is_new": is_new,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
        }
    finally:
        db.close()

    if is_new:
        flash("Account created.", "success")
    else:
        flash("Signed in.", "success")
    return redirect(url_for("dashboard"))


@app.get("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=session["user"])


@app.post("/logout")
@login_required
def logout():
    session.clear()
    post_logout = request.host_url.rstrip("/")
    if uses_microsoft():
        params = urlencode({"post_logout_redirect_uri": post_logout})
        return redirect(f"{AUTHORITY}/oauth2/v2.0/logout?{params}")
    params = urlencode({"post_logout_redirect_uri": post_logout})
    return redirect(f"{OIDC_ISSUER}/logout?{params}")


@app.get("/health")
def health():
    return {"status": "ok"}


def _microsoft_claims():
    auth_flow = session.get("auth_flow")
    if not auth_flow:
        flash("Sign-in session expired. Please try again.", "error")
        return None
    result = msal_app().acquire_token_by_auth_code_flow(auth_flow, dict(request.args))
    session.pop("auth_flow", None)
    if "error" in result:
        flash(result.get("error_description") or result.get("error"), "error")
        return None
    claims = dict(result.get("id_token_claims") or {})
    access_token = result.get("access_token")
    graph_profile = {}
    if access_token:
        try:
            response = requests.get(
                GRAPH_ME,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10,
            )
            if response.ok:
                graph_profile = response.json()
        except Exception:
            graph_profile = {}
    claims["_graph"] = graph_profile
    return claims


def _local_claims():
    flow = session.pop("oidc_flow", None)
    if not flow:
        flash("Sign-in session expired. Please try again.", "error")
        return None
    if request.args.get("state") != flow.get("state"):
        flash("Invalid sign-in state. Please try again.", "error")
        return None
    code = request.args.get("code")
    if not code:
        flash("Missing authorization code.", "error")
        return None
    try:
        token_response = requests.post(
            f"{OIDC_ISSUER_INTERNAL}/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "code_verifier": flow.get("code_verifier"),
            },
            timeout=10,
        )
        token_response.raise_for_status()
        id_token = token_response.json()["id_token"]
        jwk_client = PyJWKClient(f"{OIDC_ISSUER_INTERNAL}/jwks")
        signing_key = jwk_client.get_signing_key_from_jwt(id_token)
        return jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=CLIENT_ID,
            issuer=OIDC_ISSUER,
        )
    except Exception as exc:
        flash(f"Token exchange failed: {exc}", "error")
        return None


def _account_type(claims: dict) -> str:
    tid = (claims.get("tid") or "").lower()
    if tid == "local-lab":
        return "lab"
    if tid == "9188040d-6c67-4c5b-b112-36a304b66dad":
        return "personal"
    if claims.get("acct") == 1:
        return "guest"
    return "work_or_school"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=True)
