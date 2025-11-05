from email_handler import EmailMonitor
from virus_total import VirusTotalScanner
import os

class MailManager:
    def __init__(self):
        self.email_monitor = EmailMonitor()
        self.vt_scanner = VirusTotalScanner()

    def manage_mails(self):
        """Use stored outputs from EmailMonitor and VirusTotalScanner to delete malicious emails"""
        print("\n⚙️ Starting mail management process...")

        # 2️⃣ Scan saved mails in 'mails' folder
        folder_name = "mails"
        if not os.path.exists(folder_name):
            print("❌ Folder 'mails' not found — make sure emails are saved.")
            return

        # Store {mail_id: status}
        mail_status = {}

        print("\n🚀 Starting VirusTotal scans...")
        for file_name in os.listdir(folder_name):
            if not file_name.startswith("mail_") or not file_name.endswith(".txt"):
                continue

            file_path = os.path.join(folder_name, file_name)
            mail_id = file_name.replace("mail_", "").replace(".txt", "")

            try:
                results = self.vt_scanner.scan_file(file_path)
                status = "🚨 MALICIOUS" if results["is_malicious"] else "✅ CLEAN"
                mail_status[mail_id] = results["is_malicious"]
                print(f"{file_name} → {status}")
            except Exception as e:
                print(f"❌ Error scanning {file_path}: {e}")

        # 3️⃣ Delete malicious emails from IMAP
        # malicious_ids = [id.encode() if isinstance(id, str) else id for id in mail_id]
        malicious_ids = [m for m, is_malicious in mail_status.items() if is_malicious]
        print("Mail Id .......",malicious_ids)
        if malicious_ids:
            print("\n🧹 Deleting malicious emails from mailbox...")
            self.delete_mails(malicious_ids)
        else:
            print("\n✅ No malicious emails found.")

    def delete_mails(self, malicious_ids):
        """Deletes given mail IDs from IMAP mailbox"""
        try:
            mail = self.email_monitor.connect_to_email()
            mail.select("inbox")

            for mail_id in malicious_ids:
                # Ensure IMAP ID format is bytes, e.g. [b'55']
                if isinstance(mail_id, int):
                    imap_id = str(mail_id).encode()
                elif isinstance(mail_id, str):
                    imap_id = mail_id.encode()
                else:
                    imap_id = mail_id  # already bytes

                try:
                    mail.store(imap_id, "+FLAGS", "\\Deleted")
                    print(f"🗑️ Deleted mail ID: {imap_id}")
                except Exception as e:
                    print(f"⚠️ Failed to delete mail ID {imap_id}: {e}")

            mail.expunge()
            mail.close()
            mail.logout()
            print("✅ Malicious emails deleted successfully.")
        except Exception as e:
            print(f"❌ Error deleting emails: {e}")


    def cleanup_local_mails(self, folder_name):
        """Deletes all mail files from the local 'mails' folder after processing"""
        try:
            if not os.path.exists(folder_name):
                print("📁 'mails' folder not found for cleanup.")
                return

            print("\n🧽 Cleaning up local 'mails' folder...")
            count = 0
            for file_name in os.listdir(folder_name):
                file_path = os.path.join(folder_name, file_name)
                if os.path.isfile(file_path):
                    os.remove(file_path)
                    count += 1

            print(f"🧹 Deleted {count} mail files from '{folder_name}' folder.")
        except Exception as e:
            print(f"⚠️ Error cleaning up mails folder: {e}")


# if __name__ == "__main__":
#     manager = MailManager()
#     manager.manage_mails()
    # manager.delete_mails()
    # manager.cleanup_local_mails("mails")

