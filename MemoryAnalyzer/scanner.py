import pickle
import pandas as pd
import sys

# Load the trained model and scaler
with open('model.pkl', 'rb') as f:
    model = pickle.load(f)
with open('scaler.pkl', 'rb') as f:
    scaler = pickle.load(f)

def scan_file(csv_file):
    """
    Scan a file (CSV with memory dump features) and predict if it's malware or benign.
    
    The CSV should contain the same 56 features used in training.
    """
    try:
        # Load the data
        data = pd.read_csv(csv_file)
        
        # Remove 'Category' column if present
        if 'Category' in data.columns:
            data = data.drop('Category', axis=1)
        
        # Remove 'Class' column if present (prediction target)
        if 'Class' in data.columns:
            data = data.drop('Class', axis=1)
        
        # Scale the features
        data_scaled = scaler.transform(data)
        
        # Make predictions
        predictions = model.predict(data_scaled)
        probabilities = model.predict_proba(data_scaled)
        
        # Map predictions to labels
        label_map = {0: 'Benign', 1: 'Malware'}
        
        print(f"\n[*] Scanning {csv_file}...\n")
        for i, (pred, probs) in enumerate(zip(predictions, probabilities)):
            label = label_map[pred]
            confidence = max(probs) * 100
            print(f"Sample {i+1}: {label} (Confidence: {confidence:.2f}%)")
            print(f"  - Benign: {probs[0]*100:.2f}%")
            print(f"  - Malware: {probs[1]*100:.2f}%\n")
        
        # Overall statistics
        malware_count = sum(predictions == 1)
        benign_count = sum(predictions == 0)
        print(f"Summary:")
        print(f"  Total Malware: {malware_count}")
        print(f"  Total Benign: {benign_count}")
        
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <path_to_csv_file>")
        print("\nExample: python scanner.py sample_data.csv")
        sys.exit(1)
    
    csv_file = sys.argv[1]
    scan_file(csv_file)
