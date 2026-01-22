import pickle
import pandas as pd
import os

# Load the trained model and scaler
with open('model.pkl', 'rb') as f:
    model = pickle.load(f)
with open('scaler.pkl', 'rb') as f:
    scaler = pickle.load(f)

def scan_file(csv_file):
    """
    Scan a file (CSV with memory dump features) and predict if it's malware or benign.
    """
    try:
        # Check if file exists
        if not os.path.exists(csv_file):
            print(f"[!] Error: File '{csv_file}' not found!")
            return
        
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
        
        print(f"\n{'='*60}")
        print(f"[*] Scanning: {csv_file}")
        print(f"{'='*60}\n")
        
        has_malware = False
        for i, (pred, probs) in enumerate(zip(predictions, probabilities)):
            label = label_map[pred]
            confidence = max(probs) * 100
            
            if pred == 1:  # Malware detected
                print(f"[!] Sample {i+1}: NOT SAFE - {label} DETECTED!")
                has_malware = True
            else:
                print(f"[✓] Sample {i+1}: SAFE - {label}")
            
            print(f"    Confidence: {confidence:.2f}%")
            print(f"    Benign: {probs[0]*100:.2f}% | Malware: {probs[1]*100:.2f}%\n")
        
        # Overall statistics
        malware_count = sum(predictions == 1)
        benign_count = sum(predictions == 0)
        
        print(f"{'='*60}")
        print(f"SUMMARY:")
        print(f"  Total Samples: {len(predictions)}")
        print(f"  Benign: {benign_count}")
        print(f"  Malware: {malware_count}")
        print(f"{'='*60}\n")
        
        if has_malware:
            print("[!] WARNING: MALWARE DETECTED - NOT SAFE!")
        else:
            print("[✓] All samples are SAFE!")
        
        print(f"{'='*60}\n")
        
    except Exception as e:
        print(f"[!] Error: {e}\n")

def main():
    print("\n" + "="*60)
    print("         MEMORY MALWARE SCANNER")
    print("="*60 + "\n")
    
    while True:
        csv_file = input("[*] Enter path to CSV file (or 'quit' to exit): ").strip()
        
        if csv_file.lower() == 'quit':
            print("\n[*] Exiting scanner. Goodbye!\n")
            break
        
        if csv_file:
            scan_file(csv_file)
        else:
            print("[!] Please enter a valid path.\n")

if __name__ == "__main__":
    main()
