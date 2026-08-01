import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib
import os

# ==========================================
# ENTERPRISE DATA INGESTION
# ==========================================
# Pointing directly to your Kaggle file
DATASET_PATH = "phishing_email.csv"

print("[*] Booting AI Training Sequence...")

# Check if the massive CSV file exists in the folder
if os.path.exists(DATASET_PATH):
    print(f"[+] Found {DATASET_PATH}! Loading massive enterprise dataset...")
    try:
        # Read the CSV 
        df = pd.read_csv(DATASET_PATH)
        df = df.dropna() # Remove any empty rows
        
        # Smart Column Detection (Kaggle formats vary)
        text_col, label_col = None, None
        
        if "Email Text" in df.columns and "Email Type" in df.columns:
            text_col, label_col = "Email Text", "Email Type"
        elif "text" in df.columns and "label" in df.columns:
            text_col, label_col = "text", "label"
        elif "text_combined" in df.columns and "label" in df.columns:
            text_col, label_col = "text_combined", "label"
        elif "Message" in df.columns and "Category" in df.columns:
            text_col, label_col = "Message", "Category"
        else:
            print(f"[-] Error: Unrecognized columns. Found: {df.columns.tolist()}")
            exit()
            
        X_data = df[text_col] 
        y_data = df[label_col]
        print(f"[+] Successfully loaded {len(df)} emails for training!")
        
    except Exception as e:
        print(f"[-] Error reading CSV format. Error: {e}")
        exit()
else:
    print(f"[-] No '{DATASET_PATH}' found. Falling back to small demo dataset...")
    data = {
        "text": [
            "Hey, are we still on for the meeting at 3pm?",
            "URGENT: Your bank account has been locked. Click here to verify your identity immediately.",
            "Please review the attached invoice for last month's software subscription.",
            "SECURITY ALERT: We detected unauthorized login attempts. Reset your password at this link.",
            "Can you send me the notes from yesterday's computer science lecture?",
            "You have won a free $1000 Walmart Gift Card! Click the link below to claim your prize.",
            "Your package delivery failed. Please pay the $2.99 shipping fee to reschedule.",
            "Happy birthday! Hope you have a fantastic day today.",
            "IT NOTIFICATION: Mandatory password update required for all college staff within 24 hours.",
            "Let's grab lunch at the cafeteria tomorrow."
        ],
        "label": ["Safe", "Phishing", "Safe", "Phishing", "Safe", "Phishing", "Phishing", "Safe", "Phishing", "Safe"]
    }
    df = pd.DataFrame(data)
    X_data = df["text"]
    y_data = df["label"]

# ==========================================
# MODEL TRAINING PIPELINE
# ==========================================
print("[*] Vectorizing text data (TF-IDF)...")
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(X_data)
y = y_data

print("[*] Splitting dataset into Training and Testing sets...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print("[*] Training Advanced Random Forest Classifier (This may take a minute on large datasets)...")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1) # n_jobs=-1 uses all CPU cores!
model.fit(X_train, y_train)

# Test Accuracy
predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)
print(f"\n[===========================================]")
print(f"[+] FINAL AI MODEL ACCURACY: {accuracy * 100:.2f}%")
print(f"[===========================================]\n")

print("[*] Exporting Enterprise AI Brain to disk...")
joblib.dump(vectorizer, "tfidf_vectorizer.pkl")
joblib.dump(model, "phishing_detector_model.pkl")

print("[+] SUCCESS! New AI Brain is ready to be loaded by your IMAP Sentinel.")