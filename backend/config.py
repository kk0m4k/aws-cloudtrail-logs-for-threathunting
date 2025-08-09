from pydantic_settings import BaseSettings
from typing import Optional
import os

class Settings(BaseSettings):
    app_name: str = "CloudTrail Threat Hunting API"
    version: str = "1.0.0"
    debug: bool = False
    
    # API Configuration
    host: str = "0.0.0.0"
    port: int = 8000
    cors_origins: list = ["http://localhost:8501", "http://localhost:3000"]
    
    # Data Configuration
    data_dir: str = os.path.join(os.path.dirname(os.path.dirname(__file__)), "output")
    cache_ttl: int = 300  # 5 minutes
    max_logs_per_request: int = 10000
    
    # Performance
    enable_cache: bool = True
    cache_size_mb: int = 100
    
    class Config:
        env_prefix = "CLOUDTRAIL_"

settings = Settings()