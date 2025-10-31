# Imports
from fastapi import APIRouter, Depends, File, UploadFile, Form, Request, HTTPException
from sqlalchemy.orm import Session
from deepface import DeepFace

from spotify_helpers import AutoCreatePlaylistIfEnabled, GetSpotifyHeaders
from database import SessionLocal, UserToken, TrackHistory
from main import GetSessionData, RefreshAccessToken

import requests, tempfile, datetime

router = APIRouter()

# ------------------------
# Helper Functions
# ------------------------
def GetDatabase():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ------------------------
# Mood Mapping
# ------------------------
MoodProfiles = {
    "happy": {"genres": "pop,indie", "valence": 0.85, "energy": 0.6},
    "energetic": {"genres": "edm,hip-hop", "valence": 0.75, "energy": 0.85},
    "calm": {"genres": "chill,acoustic,ambient", "valence": 0.55, "energy": 0.25},
    "sad": {"genres": "sad,indie", "valence": 0.2, "energy": 0.3},
    "romantic": {"genres": "r-n-b,love,soul", "valence": 0.8, "energy": 0.5},
    "confident": {"genres": "hip-hop,pop", "valence": 0.7, "energy": 0.75},
    "angry": {"genres": "metal,rock", "valence": 0.3, "energy": 0.9},
    "neutral": {"genres": "pop,alt-rock", "valence": 0.5, "energy": 0.5},
    "focus": {"genres": "classical,study,lofi", "valence": 0.45, "energy": 0.3},
    "nostalgic": {"genres": "indie,folk", "valence": 0.65, "energy": 0.4},
}

EmojiToMood = {
    "😊": "happy", "😄": "happy", "😁": "happy",
    "😍": "romantic", "🥰": "romantic", "😘": "romantic",
    "😎": "confident", "🔥": "energetic", "⚡": "energetic",
    "😢": "sad", "😭": "sad", "😔": "sad",
    "😡": "angry", "🤬": "angry",
    "😴": "calm", "🧘": "calm", "🤫": "focus",
    "😐": "neutral", "🙂": "neutral", "🤔": "neutral",
    "😇": "happy", "🤯": "energetic", "😩": "sad",
    "😬": "neutral", "😌": "calm", "🥲": "nostalgic",
}

def GetMoodProfileFromEmoji(emoji: str):
    mood = EmojiToMood.get(emoji, "neutral")
    return mood, MoodProfiles[mood]

# ------------------------
# Shared Track Logging
# ------------------------
def LogTracks(db: Session, user_id: int, tracks: list[dict], mood: str, source: str):
    """Log all recommended tracks to TrackHistory."""
    try:
        for t in tracks:
            track = TrackHistory(
                UserID=user_id,
                TrackID=t.get("id"),
                TrackName=t.get("name"),
                ArtistName=", ".join([a["name"] for a in t.get("artists", [])]),
                Mood=mood,
                Source=source,
                PreviewURL=t.get("preview_url"),
                SpotifyURL=t.get("external_urls", {}).get("spotify"),
                Timestamp=datetime.datetime.now(datetime.timezone.utc)
            )
            db.add(track)
        db.commit()
    except Exception as e:
        print(f"[TrackHistory] failed to log tracks: {e}")

# ------------------------
# Routes
# ------------------------

@router.post("/mood/emoji")
def MoodFromEmoji(
        request: Request,
        emoji: str = Form(...),
        limit: int = Form(20),
        create_playlist: bool = Form(False),
        db: Session = Depends(GetDatabase),
):
    session = GetSessionData(request)
    if not session:
        raise HTTPException(status_code=401, detail="Not logged in")

    userToken = db.query(UserToken).filter(UserToken.UserID == session["user_id"]).first()
    token = RefreshAccessToken(userToken, db)

    mood, profile = GetMoodProfileFromEmoji(emoji)
    params = {
        "seed_genres": profile["genres"],
        "target_valence": profile["valence"],
        "target_energy": profile["energy"],
        "limit": limit,
    }

    r = requests.get("https://api.spotify.com/v1/recommendations", headers=GetSpotifyHeaders(token), params=params)
    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=r.text)
    tracks = r.json()["tracks"]

    # Log tracks
    LogTracks(db, userToken.ID, tracks, mood, f"emoji {emoji}")

    playlist_info = AutoCreatePlaylistIfEnabled(
        token,
        tracks,
        mood=mood,
        source=f"emoji {emoji}",
        create=create_playlist,
        db_user_id=userToken.ID
    )

    return {
        "mood": mood,
        "tracks": tracks,
        "auto_created": bool(playlist_info),
        "playlist": playlist_info
    }

@router.post("/mood/selfie")
def MoodFromSelfie(
        request: Request,
        image: UploadFile = File(...),
        limit: int = Form(20),
        create_playlist: bool = Form(False),
        db: Session = Depends(GetDatabase),
):
    session = GetSessionData(request)
    if not session:
        raise HTTPException(status_code=401, detail="Not logged in")

    userToken = db.query(UserToken).filter(UserToken.UserID == session["user_id"]).first()
    token = RefreshAccessToken(userToken, db)

    tempPath = tempfile.mktemp(suffix=".jpg")
    with open(tempPath, "wb") as f:
        f.write(image.file.read())

    try:
        analysis = DeepFace.analyze(img_path=tempPath, actions=["emotion"], enforce_detection=False)
        if isinstance(analysis, list):
            analysis = analysis[0]
        detected = analysis.get("dominant_emotion", "neutral").lower()
    except Exception as e:
        print(f"[DeepFace] failed: {e}")
        detected = "neutral"

    EmotionMap = {
        "happy": "happy", "sad": "sad", "angry": "angry",
        "fear": "sad", "disgust": "angry", "surprise": "energetic",
        "neutral": "neutral",
    }
    mood = EmotionMap.get(detected, "neutral")
    profile = MoodProfiles[mood]

    params = {
        "seed_genres": profile["genres"],
        "target_valence": profile["valence"],
        "target_energy": profile["energy"],
        "limit": limit,
    }

    r = requests.get("https://api.spotify.com/v1/recommendations", headers=GetSpotifyHeaders(token), params=params)
    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=r.text)
    tracks = r.json()["tracks"]

    # Log tracks
    LogTracks(db, userToken.ID, tracks, mood, "selfie")

    playlist_info = AutoCreatePlaylistIfEnabled(
        token,
        tracks,
        mood=mood,
        source="selfie",
        create=create_playlist,
        db_user_id=userToken.ID
    )

    return {
        "mood": mood,
        "emotion_detected": detected,
        "tracks": tracks,
        "auto_created": bool(playlist_info),
        "playlist": playlist_info
    }

