import os
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import xgboost as xgb
from ml.preprocess import load_and_preprocess
from config import settings
from utils.logger import system_logger

def train_and_evaluate(dataset_path: str = None):
    """
    Trains an XGBoost or Random Forest model on the provided dataset.
    Saves the best performing model.
    """
    system_logger.info("Initializing ML Model Training Pipeline...")
    
    # 1. Preprocess
    X_train, X_test, y_train, y_test, features_list = load_and_preprocess(dataset_path)

    # 2. Train Models
    models = {
        "RandomForest": RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
        "XGBoost": xgb.XGBClassifier(use_label_encoder=False, eval_metric='logloss')
    }

    best_model = None
    best_accuracy = 0
    best_name = ""

    for name, model in models.items():
        system_logger.info(f"Training {name}...")
        model.fit(X_train, y_train)
        
        system_logger.info(f"Evaluating {name}...")
        preds = model.predict(X_test)
        acc = accuracy_score(y_test, preds)
        
        system_logger.info(f"{name} Accuracy: {acc:.4f}")
        # print classification report to stdout directly
        print(f"\n--- {name} Classification Report ---")
        print(classification_report(y_test, preds))
        
        if acc > best_accuracy:
            best_accuracy = acc
            best_model = model
            best_name = name

    # 3. Save Best Model
    system_logger.info(f"Best model selected: {best_name} with accuracy {best_accuracy:.4f}")
    
    # Ensure directory exists
    model_dir = os.path.dirname(settings.MODEL_PATH)
    os.makedirs(model_dir, exist_ok=True)
    
    # Package model and feature list together so ML Engine knows what features to expect
    model_package = {
        "model": best_model,
        "features": features_list
    }
    
    joblib.dump(model_package, settings.MODEL_PATH)
    system_logger.info(f"Model successfully saved to {settings.MODEL_PATH}")

if __name__ == "__main__":
    # If run directly, start training.
    # Optionally pass a path to CICIDS2017 Dataset CSV here
    train_and_evaluate()
