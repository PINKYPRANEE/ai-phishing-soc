import imaplib
import email
from email.header import decode_header
import time
import re
import joblib

# ==========================================
# CONFIGURATION
# ==========================================
IMAP_SERVER = "imap.gmail.com"
EMAIL_ACCOUNT = "pinkypranee.cybertest@gmail.com"
APP_PASSWORD = "bvmvkjfijxbosncp" 
# ==========================================

# ==========================================
# LOAD THE AI BRAIN
# ==========================================
print("[*] Waking up AI Threat Detection Engine...")
try:
    vectorizer = joblib.load("tfidf_vectorizer.pkl")
    ai_model = joblib.load("phishing_detector_model.pkl")
    print("[+] AI Engine Online & Ready!\n")
except Exception as e:
    print(f"[-] CRITICAL ERROR: Could not load AI Brain. Did you run train_model.py? Error: {e}")
    exit()

def get_email_body(msg):
    """Extracts the plain text body from the raw email payload."""
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            if content_type == "text/plain" and "attachment" not in content_disposition:
                try:
                    body = part.get_payload(decode=True).decode()
                except:
                    pass
    else:
        try:
            body = msg.get_payload(decode=True).decode()
        except:
            pass
    return body

def extract_iocs(text):
    """Uses Regular Expressions to rip URLs out of the email body."""
    url_pattern = re.compile(r'(?:https?://|www\.)[^\s]+')
    return url_pattern.findall(text)

def listen_for_emails():
    """Connects to the IMAP server and checks for unread messages."""
    print(f"[*] Connecting to {IMAP_SERVER} on Port 993...")
    
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER, 993)
        mail.login(EMAIL_ACCOUNT, APP_PASSWORD)
        print("[+] Login successful! Monitoring inbox for threats...\n")
        
        while True:
            mail.select("inbox")
            status, messages = mail.search(None, "UNSEEN")
            
            email_ids = messages[0].split()
            
            if email_ids:
                print(f"[!] Found {len(email_ids)} new unread email(s)!")
                
                for e_id in email_ids:
                    res, msg_data = mail.fetch(e_id, "(RFC822)")
                    
                    for response_part in msg_data:
                        if isinstance(response_part, tuple):
                            msg = email.message_from_bytes(response_part[1])
                            
                            # Decode Subject
                            subject, encoding = decode_header(msg["Subject"])[0]
                            if isinstance(subject, bytes):
                                subject = subject.decode(encoding if encoding else "utf-8")
                                
                            sender = msg.get("From")
                            body = get_email_body(msg)
                            
                            print("=" * 60)
                            print(f"📨 NEW EMAIL INTERCEPTED")
                            print(f"From: {sender}")
                            print(f"Subject: {subject}")
                            
                            # -----------------------------------------
                            # 1. EXTRACT IOCs
                            # -----------------------------------------
                            urls = extract_iocs(body)
                            if urls:
                                print(f"\n🔗 IOCs EXTRACTED ({len(urls)}):")
                                for url in urls:
                                    print(f"    -> {url}")
                            else:
                                print("\n🔗 IOCs: None detected.")
                            
                            # -----------------------------------------
                            # 2. RUN AI CLASSIFICATION
                            # -----------------------------------------
                            # Convert the text to numbers, then ask the AI to predict
                            vectorized_body = vectorizer.transform([body])
                            prediction = ai_model.predict(vectorized_body)[0]
                            
                            print("\n🧠 AI THREAT ANALYSIS:")
                            print(f"    [DEBUG] Raw AI Output: '{prediction}'") # Reveal the true Kaggle label!
                            
                            # Make it smart enough to catch "Phishing", "1", "spam", or "malicious"
                            if str(prediction).strip().lower() in ["phishing", "1", "spam", "phishing email"]:
                                print("    🚨 VERDICT: [MALICIOUS / PHISHING DETECTED]")
                                print("    🛡️ ACTION: Email flagged for quarantine.")
                            else:
                                print("    🟢 VERDICT: [SAFE]")
                                print("    🛡️ ACTION: Email allowed to pass.")
                            
                            print("=" * 60 + "\n")
                            
            time.sleep(10)
            
    except Exception as e:
        print(f"[-] Connection failed: {e}")

if __name__ == "__main__":
    print("===========================================")
    print("   AI SOC: REAL-TIME IMAP SENTINEL ENGINE  ")
    print("===========================================\n")
    listen_for_emails()