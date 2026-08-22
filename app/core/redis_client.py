"""
Redis-backed helpers: fixed-window rate limiting for public auth endpoints,
and short-lived OAuth state storage for CSRF protection during the Google
OAuth flow.
"""

from fastapi import HTTPException
import redis
from app.config import settings

redis_client = redis.Redis.from_url(settings.redis_url, decode_responses=True)

def check_rate_limit(key:str, limit:int, window_seconds:int):
    current = redis_client.incr(key)
    if current == 1:
        redis_client.expire(key,window_seconds)
    if current > limit:
        raise HTTPException(status_code = 429, detail = "Too many requests, please try again later")

def store_oauth_state(state: str, ttl_seconds: int = 600):
    redis_client.set(f"oauth_state:{state}","1",ex = ttl_seconds)

def consume_oauth_state(state: str) -> bool:
    key = f"oauth_state:{state}"
    exists = redis_client.exists(key)
    if exists:
        redis_client.delete(key)
    return exists == 1