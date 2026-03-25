import os
import joblib
import pandas as pd
from config import settings
from utils.logger import system_logger

class MLEngine:
    """
    Machine Learning Engine for anomaly detection.
    Loads a pre-trained model (from CICIDS2017) and evaluates IP feature vectors.
    """
    def __init__(self):
        self.model_path = settings.MODEL_PATH
        self.model = None
        self.top_features = None  # Expected feature columns in order
        self.is_ready = False
        self._load_model()
        
    def _load_model(self):
        """Attempts to load the ML model and its expected features."""
        try:
            if os.path.exists(self.model_path):
                # Load model map (contains model + features list)
                model_data = joblib.load(self.model_path)
                self.model = model_data.get('model')
                self.top_features = model_data.get('features')
                self.is_ready = True
                system_logger.info("ML Engine successfully loaded trained model.")
            else:
                system_logger.warning(f"ML Model not found at {self.model_path}. ML detection disabled pending training phase.")
        except Exception as e:
            system_logger.error(f"Failed to load ML model: {e}")
            self.is_ready = False

    def evaluate(self, ip: str, features_dict: dict) -> dict:
        """
        Evaluates a feature vector against the trained ML model.
        Returns 'confidence' score and 'is_malicious' boolean.
        """
        # Default safe response if model isn't active yet
        if not self.is_ready or not self.model or not self.top_features:
            return {"is_malicious": False, "confidence": 0.0}
            
        try:
            # Reconstruct the feature vector in the strict order the model expects
            # Default to 0.0 for missing features
            ordered_features = {k: features_dict.get(k, 0.0) for k in self.top_features}
            
            # Predict using DataFrame to avoid feature name warnings from scikit-learn
            df = pd.DataFrame([ordered_features])
            
            # Get probability of class 1 (Anomaly)
            prob = self.model.predict_proba(df)[0][1]
            
            is_malicious = prob >= settings.ML_CONFIDENCE_THRESHOLD
            
            if is_malicious:
                 system_logger.warning(f"[MLEngine] IP {ip} classified as malicious (Confidence: {prob:.2f})")
                 
            return {
                "is_malicious": bool(is_malicious),
                "confidence": float(prob)
            }
            
        except Exception as e:
            system_logger.error(f"ML Evaluation failed for IP {ip}: {e}")
            return {"is_malicious": False, "confidence": 0.0}
