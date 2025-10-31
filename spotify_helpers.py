# Imports
import requests
import datetime
from database import SessionLocal, PlaylistHistory

# ---------------------------
# Helper Functions
# ---------------------------

def GetSpotifyHeaders(token: str):
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

""" Creates new Spotify playlist and returns the object. """
def CreateSpotifyPlaylist(accessToken: str, user_id: str, name: str, description: str, public: bool = False):
    payload = {"name": name, "description": description, "public": public}
    r = requests.post(
        f"https://api.spotify.com/v1/users/{user_id}/playlists",
        headers=GetSpotifyHeaders(accessToken),
        json=payload,
    )

    if r.status_code not in (200, 201):
        raise Exception(f"Failed to create Spotify playlist: {r.status_code} {r.text}")
    return r.json()

""" Adds a list of tracks (URIs) to a playlist """
def AddTracksToPlaylist(accessToken: str, playlist_id: str, track_uris: list[str]):
    if not track_uris:
        return
    r = requests.post(
        f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks",
        headers=GetSpotifyHeaders(accessToken),
        json={"uris": track_uris},
    )

    if r.status_code not in (200, 201):
        raise Exception(f"Failed to add tracks to playlist: {r.status_code} {r.text}")

""" If create=True, will automatically create new playlist, else return None """
def AutoCreatePlaylistIfEnabled(
        accessToken: str,
        tracks: list[dict],
        mood: str,
        source: str,
        create: bool,
        db_user_id: int | None = None,  # ✅ NEW PARAMETER
):
    if not create:
        return None

    # 1️⃣ Fetch current Spotify profile
    me = requests.get("https://api.spotify.com/v1/me", headers=GetSpotifyHeaders(accessToken))
    if me.status_code != 200:
        raise Exception(f"Failed to fetch profile: {me.text}")
    user_id = me.json()["id"]

    # 2️⃣ Create playlist
    playlist = CreateSpotifyPlaylist(
        accessToken,
        user_id,
        name=f"Moodify: {mood.capitalize()}",
        description=f"Generated automatically from {source}",
        public=False
    )

    # 3️⃣ Add tracks
    track_uris = [t["uri"] for t in tracks if "uri" in t]
    AddTracksToPlaylist(accessToken, playlist["id"], track_uris)

    # 4️⃣ Log playlist creation to database
    if db_user_id is not None:
        db = SessionLocal()
        try:
            entry = PlaylistHistory(
                UserID=db_user_id,  # ✅ Fixed: proper int foreign key
                Mood=mood,
                Source=source,
                SpotifyPlaylistID=playlist["id"],
                SpotifyURL=playlist["external_urls"]["spotify"],
                AutoCreated=True,
                TrackCount=len(track_uris),
                CreatedAt=datetime.datetime.now(datetime.timezone.utc)
            )
            db.add(entry)
            db.commit()
        finally:
            db.close()

    # 5️⃣ Return playlist summary
    return {
        "id": playlist["id"],
        "url": playlist["external_urls"]["spotify"],
        "name": playlist["name"],
        "total_tracks": len(track_uris),
    }

