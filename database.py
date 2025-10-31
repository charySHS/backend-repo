# Imports
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Boolean, Text
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from cryptography.fernet import Fernet
from dotenv import load_dotenv
import os, time, datetime

# -------------------------------------------------
# Load environment variables
# -------------------------------------------------
load_dotenv()
DatabaseURL = os.getenv("Database_URL", "sqlite:///./app.db")
EncryptionKey = os.getenv("EncryptionKey")
if not EncryptionKey:
    raise RuntimeError("Encryption Key not set in .env")

fernet = Fernet(EncryptionKey.encode())

engine = create_engine(DatabaseURL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# -------------------------------------------------
# USER TOKEN MODEL
# -------------------------------------------------
class UserToken(Base):
    __tablename__ = "user_tokens"
    ID = Column(Integer, primary_key=True, index=True)
    UserID = Column(String, unique=True, index=True)
    AccessTokenEnc = Column(String)
    RefreshTokenEnc = Column(String)
    RestoreToken = Column(String, unique=True, index=True)
    ExpiresAt = Column(Float)  # Store expiry timestamp

    # Relationships
    Moods = relationship("MoodHistory", back_populates="User")
    Playlists = relationship("PlaylistHistory", back_populates="User")
    Profile = relationship("UserProfile", uselist=False, back_populates="User")

    # -------------------------------------------
    # Token management
    # -------------------------------------------
    def SetTokens(self, access_token: str, refresh_token: str, expires_in: int):
        self.AccessTokenEnc = fernet.encrypt(access_token.encode()).decode()
        self.RefreshTokenEnc = fernet.encrypt(refresh_token.encode()).decode()
        self.ExpiresAt = time.time() + expires_in - 60  # Refresh 1 min early

    def GetTokens(self):
        return (
            fernet.decrypt(self.AccessTokenEnc.encode()).decode(),
            fernet.decrypt(self.RefreshTokenEnc.encode()).decode(),
            self.ExpiresAt
        )

# -------------------------------------------------
# USER PROFILE MODEL
# -------------------------------------------------
class UserProfile(Base):
    __tablename__ = "user_profiles"
    ID = Column(Integer, primary_key=True, index=True)
    UserID = Column(Integer, ForeignKey("user_tokens.ID"))
    DisplayName = Column(String)
    Email = Column(String)
    Country = Column(String)
    ProfileImageURL = Column(String, nullable=True)
    CreatedAt = Column(DateTime, default=datetime.datetime.now(datetime.UTC))
    LastLogin = Column(DateTime, default=datetime.datetime.now(datetime.UTC))
    TotalPlaylists = Column(Integer, default=0)

    User = relationship("UserToken", back_populates="Profile")

# -------------------------------------------------
# MOOD HISTORY MODEL
# -------------------------------------------------
class MoodHistory(Base):
    __tablename__ = "mood_history"
    ID = Column(Integer, primary_key=True, index=True)
    UserID = Column(Integer, ForeignKey("user_tokens.ID"))
    Mood = Column(String)
    DetectedEmotion = Column(String, nullable=True)  # e.g., from DeepFace
    SourceType = Column(String, default="emoji")     # emoji / selfie / api / text
    RecommendedTracks = Column(Text)
    Timestamp = Column(DateTime, default=datetime.datetime.now(datetime.UTC))
    PlaylistID = Column(Integer, ForeignKey("playlist_history.ID"), nullable=True)

    User = relationship("UserToken", back_populates="Moods")
    Playlist = relationship("PlaylistHistory", back_populates="MoodEntry")

# -------------------------------------------------
# PLAYLIST HISTORY MODEL
# -------------------------------------------------
class PlaylistHistory(Base):
    __tablename__ = "playlist_history"
    ID = Column(Integer, primary_key=True, index=True)
    UserID = Column(Integer, ForeignKey("user_tokens.ID"))
    Mood = Column(String)
    Source = Column(String)           # e.g., "emoji 😊", "selfie", etc.
    SpotifyPlaylistID = Column(String)
    SpotifyURL = Column(String)
    AutoCreated = Column(Boolean, default=False)
    TrackCount = Column(Integer, default=0)
    CreatedAt = Column(DateTime, default=datetime.datetime.now(datetime.UTC))

    User = relationship("UserToken", back_populates="Playlists")
    MoodEntry = relationship("MoodHistory", back_populates="Playlist")

# ---------------------------
# Track History Table
# ---------------------------
class TrackHistory(Base):
    __tablename__ = "track_history"

    ID = Column(Integer, primary_key=True, index=True)
    UserID = Column(Integer, ForeignKey("user_tokens.ID"))
    TrackID = Column(String)
    TrackName = Column(String)
    ArtistName = Column(String)
    Mood = Column(String)
    Source = Column(String)
    PreviewURL = Column(String, nullable=True)
    SpotifyURL = Column(String, nullable=True)
    Timestamp = Column(DateTime, default=datetime.datetime.now(datetime.timezone.utc))

    User = relationship("UserToken")


# -------------------------------------------------
# TRACK INSIGHTS MODEL
# -------------------------------------------------
class TrackInsight(Base):
    __tablename__ = "track_insights"
    ID = Column(Integer, primary_key=True, index=True)
    UserID = Column(Integer, ForeignKey("user_tokens.ID"))
    TrackID = Column(String, index=True)
    Name = Column(String)
    Artist = Column(String)
    Energy = Column(Float)
    Valence = Column(Float)
    Tempo = Column(Float)
    Danceability = Column(Float)
    Acousticness = Column(Float)
    Instrumentalness = Column(Float)
    CreatedAt = Column(DateTime, default=datetime.datetime.now(datetime.UTC))

    # Optional link to mood
    MoodTag = Column(String, nullable=True)

# -------------------------------------------------
# LOGIN STATE MODEL
# -------------------------------------------------
class LoginState(Base):
    __tablename__ = "login_states"
    ID = Column(Integer, primary_key=True, index=True)
    State = Column(String, unique=True, index=True)
    CreatedAt = Column(DateTime, default=datetime.datetime.now(datetime.UTC))
    ExpiresAt = Column(Float)

    def IsExpired(self):
        return not self.ExpiresAt or time.time() > float(self.ExpiresAt)

# -------------------------------------------------
# Create all tables
# -------------------------------------------------
Base.metadata.create_all(bind=engine)

