import imaplib
import email
from email.header import decode_header
import os
from config import Config

class EmailMonitor:
    def __init__(self):
        self.config = Config()

    def connect_to_email(self):
        """Connect to IMAP server"""
        try:
            mail = imaplib.IMAP4_SSL(self.config.EMAIL_SERVER, self.config.EMAIL_PORT)
            mail.login(self.config.EMAIL_USERNAME, self.config.EMAIL_PASSWORD)
            return mail
        except Exception as e:
            raise Exception(f"Failed to connect to email: {str(e)}")

    def monitor_emails(self):
        """Fetch unseen emails and return them with their IMAP IDs + total count"""
        email_connection = self.connect_to_email()
        print("✅ Successfully connected to email server!")

        # Select inbox
        status, messages = email_connection.select("inbox")
        if status == "OK":
            total_messages = int(messages[0])
            print(f"📬 Found {total_messages} email(s) in the mailbox.")
        else:
            raise Exception(f"❌ Failed to select mailbox: {status}")

        # Search for unseen emails
        status, data = email_connection.search(None, "UNSEEN")
        if status != "OK":
            print(f"❌ Failed to search for unseen emails: {status}")
            # email_connection.close()
            # email_connection.logout()
            return total_messages, {}

        email_ids = data[0].split()
        if not email_ids:
            print("📭 No new (unread) emails found.")
            # email_connection.close()
            # email_connection.logout()
            return total_messages, {}

        print(f"📨 Found {len(email_ids)} unseen email(s).")

        folder_name = "mails"
        os.makedirs(folder_name, exist_ok=True)

        email_dict = {}  # {email_id: raw_email}

        # Fetch each unseen email
        for email_id in email_ids:
            status, email_data = email_connection.fetch(email_id, "(RFC822)")
            if status == "OK":
                raw_email = email_data[0][1]
                mail_id_str = email_id.decode()

                # Save email using its ID
                filename = f"mail_{mail_id_str}.txt"
                file_path = os.path.join(folder_name, filename)

                try:
                    with open(file_path, "wb") as file:
                        file.write(raw_email)
                    print(f"💾 Saved email ID {mail_id_str} to {file_path}")
                except Exception as e:
                    print(f"⚠️ Error saving email {mail_id_str}: {e}")

                # Store the mapping
                email_dict[mail_id_str] = raw_email
            else:
                print(f"❌ Failed to fetch email with ID {email_id.decode()}")

        # Close connection cleanly
        email_connection.close()
        email_connection.logout()

        print(f"\n✅ Finished fetching {len(email_dict)} unseen email(s).")
        return total_messages, email_dict


# if __name__ == "__main__":
#     monitor = EmailMonitor()
#     total_messages, fetched_emails = monitor.monitor_emails()

#     print(f"\n📊 Total emails in mailbox: {total_messages}")
#     print(f"📨 Unseen (new) emails fetched: {len(fetched_emails)}")

#     if fetched_emails:
#         print("\n📋 Summary of fetched emails:")
#         for mail_id, raw in fetched_emails.items():
#             print(f" - Email ID {mail_id}: {len(raw)} bytes")
