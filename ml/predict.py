import json
from detection.ml_engine import MLEngine

def test_prediction():
    """
    Simple CLI utility to test the trained model against dummy data.
    """
    print("Testing ML Engine Prediction Service...")
    
    engine = MLEngine()
    if not engine.is_ready:
        print("Model not found. Please run: python ml/train_model.py first.")
        return

    # Normal profile mock
    normal_traffic = {
        "Total Fwd Packets": 10,
        "SYN Flag Count": 1,
        "Flow Duration": 500
    }

    # Attack profile mock
    attack_traffic = {
        "Total Fwd Packets": 500,
        "SYN Flag Count": 120,
        "Flow Duration": 600000
    }

    print("\nEvaluating Normal Traffic:")
    res_normal = engine.evaluate("192.168.1.100", normal_traffic)
    print(json.dumps(res_normal, indent=2))

    print("\nEvaluating Attack Traffic:")
    res_attack = engine.evaluate("10.0.0.50", attack_traffic)
    print(json.dumps(res_attack, indent=2))

if __name__ == "__main__":
    test_prediction()
