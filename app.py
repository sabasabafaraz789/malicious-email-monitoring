from flask import Flask, render_template, request
from datetime import datetime
from pathlib import Path
from config import Config
from email_handler import EmailMonitor
from virus_total import VirusTotalScanner
from delete_malicious_mails import MailManager
import os
import time

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = 'your-secret-key-here'

# Global data
email_stats = {
    'total_messages': 0,
    'new_emails': 0,
    'last_scan': 'Never'
}

scan_results = {
    'total_scanned': 0,
    'malicious_count': 0,
    'clean_count': 0,
    'last_virus_scan': 'Never',
    'scan_summary': []
}

# ✅ Reusable rendering function
def render_dashboard():
    return render_template(
        'index.html',
        total_messages=email_stats['total_messages'],
        new_emails=email_stats['new_emails'],
        last_scan=email_stats['last_scan'],

        total_scanned=scan_results['total_scanned'],
        malicious=scan_results['malicious_count'],
        clean=scan_results['clean_count'],
        time=scan_results['last_virus_scan'],
        summary=scan_results['scan_summary']
    )


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST' and 'mailbox' in request.form:
        try:
            monitor = EmailMonitor()
            total_messages, fetched_emails = monitor.monitor_emails()
            email_stats['total_messages'] = total_messages
            email_stats['new_emails'] = len(fetched_emails)
            email_stats['last_scan'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        except Exception as e:
            email_stats['error'] = str(e)
            print(f"❌ Error checking mailbox: {str(e)}")

    return render_dashboard()


@app.route('/scan_mails', methods=['GET', 'POST'])
def scanmail():
    if request.method == 'POST' and 'scan' in request.form:
        try:
            scanner = VirusTotalScanner()
            folder_path = Path("mails")

            if not folder_path.exists():
                scan_results['error'] = "Folder 'mails' not found"
                return render_dashboard()

            file_paths = [f for f in folder_path.glob("*") if f.is_file()]
            if not file_paths:
                scan_results['error'] = "No files found in 'mails' folder"
                return render_dashboard()

            summary = []
            malicious_count = clean_count = 0

            print("\n🚀 Starting VirusTotal scans...")
            for file_path in file_paths:
                try:
                    results = scanner.scan_file(str(file_path))
                    # time.sleep(5)
                    is_malicious = results.get('is_malicious', False)
                    status = "🚨 MALICIOUS" if is_malicious else "✅ CLEAN"

                    if is_malicious:
                        malicious_count += 1
                    else:
                        clean_count += 1

                    summary.append({
                        "file": os.path.basename(file_path),
                        "result": status,
                        "is_malicious": is_malicious,
                        "details": results
                    })
                    
                except Exception as e:
                    print(f"❌ Error scanning {file_path}: {str(e)}")

            # Update global scan results
            scan_results.update({
                'total_scanned': len(file_paths),
                'malicious_count': malicious_count,
                'clean_count': clean_count,
                'last_virus_scan': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'scan_summary': summary
            })    

        except Exception as e:
            scan_results['error'] = f"Error scanning mails: {str(e)}"
            print(f"❌ Error scanning mails: {str(e)}")

    return render_dashboard()





@app.route('/expunge-maliciousmails', methods=['GET', 'POST'])
def expungemails():
    if request.method == 'POST' and 'expunge' in request.form:
        try:
            manager = MailManager()
            manager.manage_mails()
            # manager.delete_mails()
            manager.cleanup_local_mails("mails")
            
            # ✅ Reset all scan statistics after deletion
            scan_results.update({
                'malicious_count': 0,
                'clean_count': 0,
                'total_scanned': 0,
                'last_virus_scan': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'scan_summary': []
            })
            
            print("✅ Malicious emails deleted and all scan counters reset")
            
        except Exception as e:
            print(f"❌ Error: {str(e)}")
    
    return render_dashboard()




# @app.route('/expunge-maliciousmails', methods=['GET', 'POST'])
# def expungemails():
#         if request.method == 'POST' and 'expunge' in request.form:
#             try:
                
#                 manager = MailManager()
#                 manager.manage_mails()
#                 # manager.delete_mails()
#                 manager.cleanup_local_mails("mails")
#             except Exception as e:
#                 print(f"❌ Error : {str(e)}")
#         return render_dashboard()


if __name__ == '__main__':
    app.run(debug=True)
