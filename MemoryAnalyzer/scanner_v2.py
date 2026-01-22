import pickle
import pandas as pd
import os
import json
import hashlib
from pathlib import Path

# Load the trained model and scaler
with open('model.pkl', 'rb') as f:
    model = pickle.load(f)
with open('scaler.pkl', 'rb') as f:
    scaler = pickle.load(f)

def get_file_hash(filepath):
    """Calculate SHA256 hash of file"""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256.update(chunk)
    return sha256.hexdigest()

def load_file_data(filepath):
    """Load data from various file formats"""
    try:
        ext = Path(filepath).suffix.lower()
        
        # Check for binary/executable files
        if ext in ['.exe', '.dll', '.bin', '.o', '.so', '.dylib']:
            print(f"[!] Error: Binary executable files cannot be scanned.")
            print(f"[!] Please provide a CSV file with extracted memory features instead.")
            return None
        
        if ext == '.csv':
            try:
                return pd.read_csv(filepath, encoding='utf-8')
            except UnicodeDecodeError:
                try:
                    return pd.read_csv(filepath, encoding='latin-1')
                except:
                    print(f"[!] Error: File encoding not supported. Use UTF-8 or Latin-1 encoded CSV.")
                    return None
        elif ext == '.json':
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        return pd.DataFrame(data)
                    else:
                        return pd.DataFrame([data])
            except UnicodeDecodeError:
                print(f"[!] Error: JSON file encoding not supported.")
                return None
        elif ext in ['.xlsx', '.xls']:
            try:
                return pd.read_excel(filepath)
            except Exception as e:
                print(f"[!] Error: Excel file format error: {str(e)}")
                return None
        elif ext == '.txt':
            try:
                return pd.read_csv(filepath, sep=r'\s+|,|\t', encoding='utf-8')
            except UnicodeDecodeError:
                try:
                    return pd.read_csv(filepath, sep=r'\s+|,|\t', encoding='latin-1')
                except:
                    print(f"[!] Error: File encoding not supported.")
                    return None
        else:
            print(f"[!] Unsupported file format: {ext}")
            print(f"[!] Supported formats: CSV, JSON, Excel (.xlsx, .xls), TXT")
            return None
    except Exception as e:
        print(f"[!] Error reading file: {e}")
        return None

def scan_file(filepath):
    """
    Scan any file type for malware based on memory features.
    Supports CSV, JSON, Excel, and TXT formats.
    """
    try:
        # Check if file exists
        if not os.path.exists(filepath):
            print(f"[!] Error: File '{filepath}' not found!")
            return
        
        print(f"\n{'='*70}")
        print(f"[*] SCANNING: {os.path.basename(filepath)}")
        print(f"[*] Path: {os.path.abspath(filepath)}")
        print(f"[*] Size: {os.path.getsize(filepath) / 1024:.2f} KB")
        
        # Get file hash
        file_hash = get_file_hash(filepath)
        print(f"[*] SHA256: {file_hash}")
        print(f"{'='*70}\n", flush=True)
        
        # Load data
        print("[*] Loading file data...")
        data = load_file_data(filepath)
        
        if data is None or data.empty:
            print("[!] Could not load data from file!")
            return
        
        print(f"[OK] Loaded {len(data)} samples with {len(data.columns)} features")
        
        # Clean data - remove non-numeric columns
        if 'Category' in data.columns:
            data = data.drop('Category', axis=1)
        if 'Class' in data.columns:
            data = data.drop('Class', axis=1)
        
        # Filter only numeric columns
        numeric_data = data.select_dtypes(include=['number'])
        
        if len(numeric_data.columns) == 0:
            print("[!] No numeric features found in file!")
            return
        
        print(f"[OK] Using {len(numeric_data.columns)} numeric features for analysis\n")
        
        # Check if we have the right number of features
        expected_features = scaler.n_features_in_
        if len(numeric_data.columns) != expected_features:
            print(f"[!] Warning: Expected {expected_features} features, got {len(numeric_data.columns)}")
            print("[*] This may affect accuracy!")
        
        # Scale the features
        data_scaled = scaler.transform(numeric_data)
        
        # Make predictions
        predictions = model.predict(data_scaled)
        probabilities = model.predict_proba(data_scaled)
        
        # Map predictions to labels
        label_map = {0: 'BENIGN', 1: 'MALWARE'}
        
        print(f"{'='*70}")
        print("SCAN RESULTS:")
        print(f"{'='*70}\n")
        
        has_malware = False
        for i, (pred, probs) in enumerate(zip(predictions, probabilities)):
            label = label_map[pred]
            confidence = max(probs) * 100
            
            if pred == 1:  # Malware detected
                status = "[NOT SAFE]"
                has_malware = True
            else:
                status = "[SAFE]"
            
            print(f"Sample {i+1}: {status} {label}")
            print(f"  |- Confidence: {confidence:.2f}%")
            print(f"  |- Benign: {probs[0]*100:.2f}% | Malware: {probs[1]*100:.2f}%")
            if i < len(predictions) - 1:
                print()
        
        # Overall statistics
        malware_count = sum(predictions == 1)
        benign_count = sum(predictions == 0)
        malware_percent = (malware_count / len(predictions)) * 100
        
        print(f"\n{'='*70}")
        print("SUMMARY:")
        print(f"{'='*70}")
        print(f"  Total Samples Analyzed: {len(predictions)}")
        print(f"  Benign Samples: {benign_count}")
        print(f"  Malware Samples: {malware_count} ({malware_percent:.1f}%)")
        print(f"{'='*70}\n")
        
        if has_malware:
            print("*** ALERT: MALWARE DETECTED ***")
            print("!!! THIS FILE IS NOT SAFE - TAKE IMMEDIATE ACTION !!!")
        else:
            print("[OK] This file appears to be SAFE.")
        
        print(f"\n{'='*70}\n")
        
    except Exception as e:
        print(f"[!] Scan error: {e}\n")

def main():
    print("\n" + "="*70)
    print(" "*15 + "ADVANCED MALWARE SCANNER v2.0")
    print(" "*10 + "Supports: CSV, JSON, Excel, TXT formats")
    print("="*70 + "\n")
    
    while True:
        filepath = input("[*] Enter file path to scan (or 'quit' to exit): ").strip()
        
        if filepath.lower() == 'quit':
            print("\n[*] Exiting scanner. Goodbye!\n")
            break
        
        if filepath:
            scan_file(filepath)
        else:
            print("[!] Please enter a valid path.\n")

if __name__ == "__main__":
    main()
