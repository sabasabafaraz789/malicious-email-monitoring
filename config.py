
import os
from datetime import timedelta
from dotenv import load_dotenv

# ✅ Load environment variables from .env file
load_dotenv()
class Config:
    # Email Configuration (IMAP)
    EMAIL_SERVER = os.getenv('EMAIL_SERVER', '')
    EMAIL_PORT = int(os.getenv('EMAIL_PORT', ))
    EMAIL_USERNAME = os.getenv('EMAIL_USERNAME', '')
    EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD', '')
    
    # VirusTotal Configuration
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
    
    # Monitoring Configuration
    SCAN_INTERVAL = int(os.getenv('SCAN_INTERVAL', 10))  # 5 minutes
    AUTO_QUARANTINE = os.getenv('AUTO_QUARANTINE', 'False').lower() == 'true'
    QUARANTINE_FOLDER = os.getenv('QUARANTINE_FOLDER', 'INBOX.Quarantine')
    
    # Flask Configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here')