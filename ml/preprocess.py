import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from utils.logger import system_logger

# Columns matching CICIDS2017 feature format that our feature_extractor emits
EXPECTED_FEATURES = [
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Flow Duration",
    "Fwd PSH Flags",
    "Fwd URG Flags",
    "Bwd PSH Flags",
    "Bwd URG Flags",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min"
]

def load_and_preprocess(csv_path: str = None):
    """
    Loads dataset, cleans invalid data, scales features, and prepares splits.
    If no CSV provided, generates synthetic mock data for demonstration.
    """
    if csv_path and pd.io.common.file_exists(csv_path):
        system_logger.info(f"Loading dataset from {csv_path}")
        df = pd.read_csv(csv_path)
    else:
        system_logger.warning("No dataset provided or file not found. Generating synthetic CICIDS2017-like data for demonstration.")
        df = generate_synthetic_data(1000)

    # Convert Label to binary (0 = Normal, 1 = Attack)
    if 'Label' in df.columns:
        df['Label'] = df['Label'].apply(lambda x: 0 if str(x).strip().lower() == 'normal' or x == 0 else 1)
    else:
        df['Label'] = np.random.choice([0, 1], size=len(df), p=[0.8, 0.2])

    system_logger.info("Cleaning invalid, NaN, and Inf values...")
    # Keep only expected features plus Label
    available_features = [col for col in EXPECTED_FEATURES if col in df.columns]
    df = df[available_features + ['Label']]

    # Fill NaNs with 0, replace Infs
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.fillna(0)

    # Features and Labels
    X = df[available_features]
    y = df['Label']

    # Train Test Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    system_logger.info(f"Preprocessing complete. Train size: {len(X_train)}, Test size: {len(X_test)}")
    
    return X_train, X_test, y_train, y_test, available_features

def generate_synthetic_data(num_samples: int):
    """Generates fake network traffic data for model training out-of-the-box."""
    np.random.seed(42)
    data = {}
    
    # Generate Normal traffic (Label 0)
    for feat in EXPECTED_FEATURES:
        data[feat] = np.random.normal(loc=10, scale=2, size=num_samples)
    
    # Introduce anomalies for Attack traffic (Label 1)
    attack_indices = np.random.choice(num_samples, size=int(num_samples * 0.2), replace=False)
    
    # Modifying specific features for attacks
    data["SYN Flag Count"][attack_indices] = np.random.normal(loc=100, scale=20, size=len(attack_indices))
    data["Flow Duration"][attack_indices] = np.random.normal(loc=500000, scale=10000, size=len(attack_indices))
    data["Total Fwd Packets"][attack_indices] = np.random.normal(loc=200, scale=50, size=len(attack_indices))
    
    df = pd.DataFrame(data)
    
    labels = np.zeros(num_samples)
    labels[attack_indices] = 1
    df['Label'] = labels
    
    return df
