"""Caching support for LLM analysis results."""

import json
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime, timedelta


class ConfigCache:
    """Cache for configuration detection results."""
    
    def __init__(self, cache_dir: Path = Path("results/config_cache"), cache_days: int = 30):
        """
        Initialize the cache.
        
        Args:
            cache_dir: Directory to store cache files
            cache_days: Number of days to keep cached results
        """
        self.cache_dir = Path(cache_dir)
        self.cache_days = cache_days
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def get_cache_key(self, build_files: Dict[str, str], model: str) -> str:
        """
        Generate a cache key from build files and model name.
        
        Args:
            build_files: Dictionary mapping filename to file content
            model: LLM model name
        
        Returns:
            Cache key (hash string)
        """
        # Create a deterministic hash from build files and model
        content = json.dumps(build_files, sort_keys=True) + model
        return hashlib.sha256(content.encode('utf-8')).hexdigest()[:16]
    
    def get(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """
        Get cached result if available and not expired.
        
        Args:
            cache_key: Cache key
        
        Returns:
            Cached result or None if not found/expired
        """
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        if not cache_file.exists():
            return None
        
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                cached = json.load(f)
            
            # Check if expired
            cached_time = datetime.fromisoformat(cached['timestamp'])
            if datetime.now() - cached_time > timedelta(days=self.cache_days):
                cache_file.unlink()  # Delete expired cache
                return None
            
            return cached['result']
        except (json.JSONDecodeError, KeyError, ValueError):
            # Invalid cache file, delete it
            cache_file.unlink()
            return None
    
    def set(self, cache_key: str, result: Dict[str, Any]):
        """
        Store result in cache.
        
        Args:
            cache_key: Cache key
            result: Result to cache
        """
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        cached = {
            'timestamp': datetime.now().isoformat(),
            'result': result
        }
        
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(cached, f, indent=2)
    
    def clear(self):
        """Clear all cache files."""
        for cache_file in self.cache_dir.glob("*.json"):
            cache_file.unlink()
    
    def cleanup_expired(self):
        """Remove expired cache files."""
        now = datetime.now()
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    cached = json.load(f)
                cached_time = datetime.fromisoformat(cached['timestamp'])
                if now - cached_time > timedelta(days=self.cache_days):
                    cache_file.unlink()
            except (json.JSONDecodeError, KeyError, ValueError):
                # Invalid cache file, delete it
                cache_file.unlink()
