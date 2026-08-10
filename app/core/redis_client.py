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
    redis_client.setex(f"oauth_state: {state}",ttl_seconds,"1")

def consume_oauth_state(state: str) -> bool:
    key = f"oauth_state:{state}"
    exists = redis_client.exists(key)
    if exists:
        redis_client.delete(key)
    return exists == 1