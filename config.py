import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # API Settings
    PROJECT_NAME: str = "Intelligent IP Tracking System"
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = True
    
    # Firebase
    FIREBASE_CREDENTIALS_PATH: str = "firebase-adminsdk.json"
    
    # Detection Engine Thresholds
    MAX_REQUESTS_PER_MINUTE: int = 100
    MAX_PORTS_SCANNED: int = 10
    ML_CONFIDENCE_THRESHOLD: float = 0.75
    
    # Packet Capture
    CAPTURE_INTERFACE: str | None = None  # None uses default interface
    
    # Paths
    BASE_DIR: str = os.path.dirname(os.path.abspath(__file__))
    MODEL_PATH: str = os.path.join(BASE_DIR, "ml", "models", "ids_model.joblib")
    
    class Config:
        env_file = ".env"

settings = Settings()
