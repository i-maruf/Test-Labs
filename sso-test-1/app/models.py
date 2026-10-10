from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, UniqueConstraint, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()


class IdpAccount(Base):
    __tablename__ = "idp_accounts"
    __table_args__ = (UniqueConstraint("email", name="uq_idp_accounts_email"),)

    id = Column(Integer, primary_key=True)
    oid = Column(String(128), nullable=False, unique=True)
    email = Column(String(320), nullable=False)
    name = Column(String(256), nullable=True)
    given_name = Column(String(128), nullable=True)
    family_name = Column(String(128), nullable=True)
    password_hash = Column(String(256), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class IdpAuthCode(Base):
    __tablename__ = "idp_auth_codes"

    code = Column(String(128), primary_key=True)
    account_id = Column(Integer, nullable=False)
    client_id = Column(String(128), nullable=False)
    redirect_uri = Column(String(512), nullable=False)
    nonce = Column(String(256), nullable=True)
    code_challenge = Column(String(256), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("oid", name="uq_users_oid"),)

    id = Column(Integer, primary_key=True)
    oid = Column(String(128), nullable=False)
    email = Column(String(320), nullable=True, index=True)
    name = Column(String(256), nullable=True)
    given_name = Column(String(128), nullable=True)
    family_name = Column(String(128), nullable=True)
    tenant_id = Column(String(64), nullable=True)
    account_type = Column(String(32), nullable=True)
    last_flow = Column(String(16), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_login_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


def make_engine(database_url: str):
    return create_engine(database_url, pool_pre_ping=True)


def make_session_factory(database_url: str):
    return sessionmaker(bind=make_engine(database_url))
