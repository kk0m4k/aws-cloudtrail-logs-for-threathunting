from typing import Any, Optional, Dict
import time
import hashlib
import json
from functools import wraps
import asyncio
from datetime import datetime
from pydantic import BaseModel

from config import settings

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, BaseModel):
            return obj.model_dump()
        return super().default(obj)

class CacheService:
    def __init__(self):
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._enabled = settings.enable_cache
        self._ttl = settings.cache_ttl
        self._max_size_bytes = settings.cache_size_mb * 1024 * 1024
        self._current_size = 0
        
    def _generate_key(self, prefix: str, params: Dict[str, Any]) -> str:
        """Generate cache key from parameters"""
        param_str = json.dumps(params, sort_keys=True, cls=DateTimeEncoder)
        hash_obj = hashlib.md5(param_str.encode())
        return f"{prefix}:{hash_obj.hexdigest()}"
    
    def _estimate_size(self, value: Any) -> int:
        """Estimate size of cached value in bytes"""
        return len(json.dumps(value, cls=DateTimeEncoder).encode())
    
    def _evict_oldest(self):
        """Evict oldest entries when cache is full"""
        if not self._cache:
            return
        
        # Sort by timestamp and remove oldest
        sorted_items = sorted(
            self._cache.items(), 
            key=lambda x: x[1]['timestamp']
        )
        
        # Remove oldest 10% of entries
        to_remove = max(1, len(sorted_items) // 10)
        for key, _ in sorted_items[:to_remove]:
            entry = self._cache.pop(key)
            self._current_size -= entry['size']
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        if not self._enabled:
            return None
        
        if key in self._cache:
            entry = self._cache[key]
            # Check if expired
            if time.time() - entry['timestamp'] > self._ttl:
                self._current_size -= entry['size']
                del self._cache[key]
                return None
            return entry['value']
        return None
    
    def set(self, key: str, value: Any):
        """Set value in cache"""
        if not self._enabled:
            return
        
        size = self._estimate_size(value)
        
        # Check if we need to evict entries
        while self._current_size + size > self._max_size_bytes and self._cache:
            self._evict_oldest()
        
        # Remove old entry if exists
        if key in self._cache:
            old_entry = self._cache[key]
            self._current_size -= old_entry['size']
        
        # Add new entry
        self._cache[key] = {
            'value': value,
            'timestamp': time.time(),
            'size': size
        }
        self._current_size += size
    
    def clear(self):
        """Clear all cache entries"""
        self._cache.clear()
        self._current_size = 0
    
    def stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return {
            'enabled': self._enabled,
            'entries': len(self._cache),
            'size_mb': self._current_size / (1024 * 1024),
            'max_size_mb': settings.cache_size_mb,
            'ttl_seconds': self._ttl
        }

def cache_result(prefix: str):
    """Decorator for caching async function results"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Determine if this is a method call (first arg is self) or a regular function
            if args and hasattr(args[0], '_cache'):
                # Method call with self
                self = args[0]
                cache_instance = self._cache
                func_args = args[1:]
            else:
                # Regular function - use global cache
                cache_instance = cache
                func_args = args
            
            # Skip caching if disabled
            if not cache_instance._enabled:
                return await func(*args, **kwargs)
            
            # Generate cache key
            cache_params = {
                'args': func_args,
                'kwargs': kwargs
            }
            cache_key = cache_instance._generate_key(prefix, cache_params)
            
            # Check cache
            cached = cache_instance.get(cache_key)
            if cached is not None:
                return cached
            
            # Execute function
            result = await func(*args, **kwargs)
            
            # Cache result
            cache_instance.set(cache_key, result)
            
            return result
        return wrapper
    return decorator

# Global cache instance
cache = CacheService()