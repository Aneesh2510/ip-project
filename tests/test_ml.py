import pytest
import os
from ml.preprocess import load_and_preprocess

def test_preprocess_synthetic_generation():
    # If no real CSV is passed, it should mock data
    X_train, X_test, y_train, y_test, features = load_and_preprocess(None)
    
    # Check that splits are created properly
    assert len(X_train) == 800
    assert len(X_test) == 200
    assert len(y_train) == 800
    assert len(y_test) == 200
    
    # Check that labels exist and are binary
    assert set(y_train.unique()).issubset({0, 1})
    
    # Check that expected features are extracted
    assert "Total Fwd Packets" in features
    assert "Flow Duration" in features
