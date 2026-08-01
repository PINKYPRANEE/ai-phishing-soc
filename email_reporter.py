import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import os

# ==========================================
# ⚙️ CONFIGURATION
# ==========================================
SENDER_EMAIL = "pinkypranee.cybertest@gmail.com"  
APP_PASSWORD = "bvmvkjfijxbosncp"     
RECEIVER_EMAIL = "apal.cse2024@rmd.ac.in" 
LOG_FILE_PATH = "soc_alerts.log"

def generate_report():
    print("[*] Reading SOC alerts log...")
    if not os.path.exists(LOG_FILE_PATH):
        return "No alerts recorded today. The network is secure."

    with open(LOG_FILE_PATH, "r") as file:
        logs = file.readlines()

    total_alerts = len(logs)
    report_body = f"<h2>Daily SOC Threat Summary</h2>"
    report_body += f"<p><b>Total Alerts Logged:</b> {total_alerts}</p><hr>"
    
    # Grab the last 5 alerts for the email summary
    report_body += "<h3>Recent Threat Activity:</h3><ul>"
    for log in logs[-5:]: 
        report_body += f"<li>{log.strip()}</li>"
    report_body += "</ul>"
    
    return report_body

def send_email(html_content):
    print("[*] Connecting to email server...")
    
    # Set up the email headers
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"🚨 AI SOC Daily Report - {datetime.now().strftime('%Y-%m-%d')}"
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL

    # Attach the HTML body
    part = MIMEText(html_content, "html")
    msg.attach(part)

    try:
        # Connect to Gmail's secure SMTP server
        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.login(SENDER_EMAIL, APP_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        server.quit()
        print("[+] SUCCESS: SOC Daily Report sent to your inbox!")
    except Exception as e:
        print(f"[-] ERROR: Failed to send email. Details: {e}")

if __name__ == "__main__":
    print("=========================================")
    print("  AI SOC: AUTOMATED REPORT GENERATOR")
    print("=========================================")
    report_html = generate_report()
    send_email(report_html)