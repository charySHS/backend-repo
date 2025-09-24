# Imports
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from cryptography.fernet import Fernet
from dotenv import load_dotenv

import os, time, datetime

# Load Variables
load_dotenv()

DatabaseURL = os.getenv("Database_URL", "sqlite:///./app.db")
EncryptionKey = os.getenv("EncryptionKey")
if not EncryptionKey:
    raise RuntimeError("Encryption Key not set in .env")

fernet = Fernet(EncryptionKey.encode())

engine = create_engine(DatabaseURL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# Token model
class UserToken(Base):
    __tablename__ = "user_tokens"
    ID = Column(Integer, primary_key=True, index=True)
    UserID = Column(String, unique=True, index=True)
    AccessTokenEnc = Column(String)
    RefreshTokenEnc = Column(String)
    RestoreToken = Column(String, unique=True, index=True)
    ExpiresAt = Column(Float) # store expiry time as timestamp

    Moods = relationship("MoodHistory", back_populates="User")

    def SetTokens(self, access_token: str, refresh_token: str, expires_in: int):
        self.AccessTokenEnc = fernet.encrypt(access_token.encode()).decode()
        self.RefreshTokenEnc = fernet.encrypt(refresh_token.encode()).decode()
        self.ExpiresAt = time.time() + expires_in - 60 # Refresh 1 min early

    def GetTokens(self):
        return (
            fernet.decrypt(self.AccessTokenEnc.encode()).decode(),
            fernet.decrypt(self.RefreshTokenEnc.encode()).decode(),
            self.ExpiresAt
        )

# ---------------------------
# Mood History Table
# ---------------------------
class MoodHistory(Base):
    __tablename__ = "mood_history"
    ID = Column(Integer, primary_key=True, index=True)
    UserID = Column(Integer, ForeignKey("user_tokens.ID"))
    Mood = Column(String)
    RecommendedTracks = Column(String)
    Timestamp = Column(DateTime, default=datetime.datetime.now(datetime.UTC))

    User = relationship("UserToken", back_populates="Moods")

# --------------------------
# User Profile Table
# --------------------------
class UserProfile(Base):
    __tablename__ = "user_profiles"
    ID = Column(Integer, primary_key=True, index=True)
    UserID = Column(Integer, ForeignKey("user_tokens.ID"))
    DisplayName = Column(String)
    Country = Column(String)
    Email = Column(String)
    CreatedAt = Column(DateTime, default=datetime.datetime.now(datetime.UTC))

    User = relationship("UserToken")

Base.metadata.create_all(bind=engine)
