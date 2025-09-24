# Imports
from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.responses import RedirectResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from dotenv import load_dotenv

from database import SessionLocal, UserToken
from typing import Optional, Dict, Any

import requests, os, base64, time, secrets

# Load environment variables
load_dotenv()

SpotifyClientID = os.getenv("Spotify_Client_ID")
SpotifyClientSecret = os.getenv("Spotify_Client_Secret")
SpotifyRedirectURL = os.getenv("Spotify_Redirect_URL", "http://127.0.0.1:8888/callback")
SessionSecret = os.getenv("Session_Secret", "dev-secret-key") # use secure 256-bit value in production

app = FastAPI(title="Mood Generator API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # TODO: Replace with production frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

serializer = URLSafeTimedSerializer(SessionSecret)

# ------------------------
# Session Helper Functions
# ------------------------
def MakeBasicAuthHeader() -> Dict[str, str]:
    # Generates Spotify Basic Auth header for token exchanges
    authString = f"{SpotifyClientID}:{SpotifyClientSecret}"
    encoded = base64.b64encode(authString.encode()).decode()

    return {"Authorization": f"Basic {encoded}"}

def FetchSpotifyDisplayName(access_token:str) -> str:
    # Fetch Spotify display name given in access token
    r = requests.get("https://api.spotify.com/v1/me", headers={"Authorization": f"Bearer {access_token}"})
    if r.status_code != 200:
        return "Spotify User"

    return r.json().get("display_name", "Spotify User")

def CreateSessionCookie(user_id: str, extra_data: Optional[dict] = None) -> str:
    """Serialize user ID + optional extra data into a signed cookie."""
    payload = {"user_id": user_id}
    if extra_data:
        payload.update(extra_data)

    payload["crsf_token"] = secrets.token_urlsafe(16)

    return serializer.dumps(payload)

def GetSessionData(request: Request) -> Optional[Dict[str, Any]]:
    """Load signed session cookie and return all stored data."""
    cookie = request.cookies.get("session")
    if not cookie:
        return None
    try:
        return serializer.loads(cookie, max_age=3600 * 24 * 7)  # 7-day session
    except (BadSignature, SignatureExpired):
        return None

def RefreshAccessToken(user_token: UserToken, db) -> str:
    """Refresh Spotify access token if expired and return a valid one."""
    accessToken, refreshToken, expiresAt = user_token.GetTokens()
    if expiresAt > time.time():  # still valid
        return accessToken

    payload = {
        "grant_type": "refresh_token",
        "refresh_token": refreshToken
    }

    r = requests.post("https://accounts.spotify.com/api/token", data=payload, headers=MakeBasicAuthHeader())
    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=f"Token refresh failed: {r.text}")

    tokenData = r.json()
    newAccess = tokenData["access_token"]
    expiresIn = tokenData.get("expires_in", 3600)

    user_token.SetTokens(newAccess, refreshToken, expiresIn)
    db.add(user_token)
    db.commit()

    return newAccess

def GenerateRestoreToken() -> str:
    # Generates a cryptographically secure, URL-safe restore token
    return secrets.token_urlsafe(32)

# ------------------------
# Routes
# ------------------------
@app.get("/login")
def login(force: bool = False, request: Request = None) -> RedirectResponse:
    if not SpotifyClientID:
        raise HTTPException(status_code=500, detail="Spotify Client ID is not set.")
    if not SpotifyRedirectURL:
        raise HTTPException(status_code=500, detail="Spotify Redirect URL is not set.")

    db = SessionLocal()
    userID = None

    if request:
        session = GetSessionData(request)
        if session:
            userID = session.get("user_id")

    if userID and not force:
        userToken = db.query(UserToken).filter(UserToken.UserID == userID).first()
        if userToken:
            db.close()
            return RedirectResponse(url="/welcome")

    db.close()
    scope = "playlist-modify-private playlist-read-private"
    authURL = (
        "https://accounts.spotify.com/authorize"
        f"?client_id={SpotifyClientID}"
        f"&response_type=code"
        f"&redirect_uri={SpotifyRedirectURL}"
        f"&scope={scope}"
    )
    return RedirectResponse(authURL)

@app.get("/callback")
def callback(code: str) -> RedirectResponse:
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": SpotifyRedirectURL
    }

    r = requests.post("https://accounts.spotify.com/api/token", data=payload, headers=MakeBasicAuthHeader())
    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=f"Spotify token request failed: {r.text}")

    tokenData = r.json()
    accessToken = tokenData["access_token"]
    refreshToken = tokenData["refresh_token"]
    expiresIn = tokenData["expires_in"]

    # Fetch Spotify profile for UserID + display name
    profileResponse = requests.get(
        "https://api.spotify.com/v1/me",
        headers={"Authorization": f"Bearer {accessToken}"}
    )
    if profileResponse.status_code != 200:
        raise HTTPException(status_code=profileResponse.status_code, detail="Failed to fetch profile")

    profileData = profileResponse.json()
    userID = profileData["id"]
    displayName = profileData.get("display_name", "Spotify User")

    db = SessionLocal()
    userToken = db.query(UserToken).filter(UserToken.UserID == userID).first()
    if not userToken:
        userToken = UserToken(UserID=userID)
        db.add(userToken)

    userToken.SetTokens(accessToken, refreshToken, expiresIn)

    userToken.RestoreToken = GenerateRestoreToken()
    db.add(userToken)
    db.commit()

    # Set signed cookie with display name included
    cookieVal = CreateSessionCookie(userID, extra_data={"display_name": displayName})
    response = RedirectResponse(url="/welcome")
    response.set_cookie("session", cookieVal, httponly=True, max_age=3600 * 24 * 7)
    db.close()
    return response

@app.get("/welcome")
def welcome(request: Request) -> Dict[str, str]:
    session = GetSessionData(request)
    if not session:
        raise HTTPException(status_code=401, detail="Not logged in")
    return {"message": f"Welcome, {session.get('display_name', session['user_id'])}!"}

@app.get("/logout")
def logout(request: Request, full_logout: bool = False) -> JSONResponse:
    """
    Clear the session cookie but leave tokens in the DB
    so the user can log back in silently later if desired.
    """
    session = GetSessionData(request)
    if session and full_logout:
        db = SessionLocal()
        userToken = db.query(UserToken).filter(UserToken.UserID == session["user_id"]).first()
        if userToken:
            db.delete(userToken)
            db.commit()
        db.close()

    response = JSONResponse({"message": "Logged out successfully."})
    response.delete_cookie("session")

    return response

@app.get("/revoke")
def revoke(request: Request) -> JSONResponse:
    """
    Fully revokes tokens and session.
    """
    session = GetSessionData(request)
    if not session:
        raise HTTPException(status_code=401, detail="Not logged in")

    db = SessionLocal()
    userToken = db.query(UserToken).filter(UserToken.UserID == session["user_id"]).first()
    if userToken:
        db.delete(userToken)
        db.commit()
    db.close()

    response = JSONResponse({"message": "All tokens revoked and session cleared."})
    response.delete_cookie("session")

    return response

@app.get("/restore-session")
def restore_session(request: Request) -> JSONResponse:
    """
    Recreates session cookie silently if tokens exist for a given user.
    This allows "remember me" functionality after logout or browser refresh.
    :param request:
    :return:
    """
    restoreToken = request.headers.get("x-restore-token")
    if not restoreToken:
        raise HTTPException(status_code=401, detail="Missing restore token")

    db = SessionLocal()
    userToken = db.query(UserToken).filter(UserToken.RestoreToken == restoreToken).first()
    if not userToken:
        db.close()
        raise HTTPException(status_code=401, detail="Invalid restore token")

    # Refresh token if needed
    accessToken = RefreshAccessToken(userToken, db)

    # Fetch display name from Spotify to keep up-to-date
    displayName = FetchSpotifyDisplayName(accessToken)

    cookieVal = CreateSessionCookie(userToken.UserID, extra_data={"display_name": displayName})
    response = JSONResponse({"message": "Session restored", "display_name": displayName})
    response.set_cookie("session", cookieVal, httponly=True, max_age=3600 * 24 * 7)
    db.close()

    return response

@app.get("/recommendations")
def recommendations(request: Request, mood: str) -> JSONResponse:
    moodMap = {
        "happy": {"minValence": 0.6, "minEnergy": 0.5},
        "sad": {"maxValence": 0.3, "maxEnergy": 0.4},
        "chill": {"minValence": 0.4, "maxEnergy": 0.5},
        "angry": {"minValence": 0.2, "maxValence": 0.5, "minEnergy": 0.8}
    }

    if mood not in moodMap:
        raise HTTPException(status_code=400, detail="Unknown mood")

    session = GetSessionData(request)
    if not session:
        raise HTTPException(status_code=401, detail="Not logged in")

    db = SessionLocal()
    userToken = db.query(UserToken).filter(UserToken.UserID == session["user_id"]).first()
    if not userToken:
        db.close()
        raise HTTPException(status_code=401, detail="No tokens stored")

    accessToken = RefreshAccessToken(userToken, db)
    db.close()

    params = {**moodMap[mood], "limit": 10, "seed_genres": "pop"}
    r = requests.get(
        "https://api.spotify.com/v1/recommendations",
        params=params,
        headers={"Authorization": f"Bearer {accessToken}"}
    )

    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=f"Spotify recommendations failed: {r.text}")

    return JSONResponse(content=r.json())

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    FilePath = os.path.join(os.path.dirname(__file__), "favicon.ico")
    if os.path.exists(FilePath):
        return FileResponse(FilePath)

    return JSONResponse({"detail": "No favicon set"}, status_code=404)
