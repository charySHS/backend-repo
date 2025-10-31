# analytics_routes.py
from fastapi import APIRouter, Depends, Request, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from database import SessionLocal, TrackHistory, UserToken
from main import GetSessionData

import datetime

router = APIRouter()

# ------------------------
# Database Helper
# ------------------------
def GetDatabase():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ------------------------
# Analytics Routes
# ------------------------

@router.get("/analytics/moods")
def MoodAnalytics(
        request: Request,
        db: Session = Depends(GetDatabase),
        days: int = Query(default=30, description="How many past days to analyze"),
        source: str | None = Query(default=None, description="Filter by 'emoji' or 'selfie'"),
):
    """
    Aggregate mood counts over a time window (default 30 days).
    Optionally filter by source type.
    """
    session = GetSessionData(request)
    if not session:
        raise HTTPException(status_code=401, detail="Not logged in")

    userToken = db.query(UserToken).filter(UserToken.UserID == session["user_id"]).first()
    if not userToken:
        raise HTTPException(status_code=401, detail="Missing tokens")

    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)

    query = db.query(TrackHistory.Mood, func.count(TrackHistory.Mood)) \
        .filter(TrackHistory.UserID == userToken.ID) \
        .filter(TrackHistory.Timestamp >= cutoff)

    if source:
        query = query.filter(TrackHistory.Source == source)

    query = query.group_by(TrackHistory.Mood).order_by(func.count(TrackHistory.Mood).desc())
    results = query.all()

    return {mood: count for mood, count in results}
