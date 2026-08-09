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
