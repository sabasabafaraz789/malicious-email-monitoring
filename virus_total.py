import requests
import os
import hashlib
import time
from config import Config
from pathlib import Path

class VirusTotalScanner:
    def __init__(self):
        self.api_key = Config.VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key}

    def compute_sha256(self, file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    def get_analysis_stats(self, file_hash):
        """Try fetching existing report, return None if not found."""
        url = f"{self.base_url}/files/{file_hash}"
        response = requests.get(url, headers=self.headers)
        if response.status_code == 404:
            # Not found — must upload file
            return None, 0
        if response.status_code != 200:
            raise Exception(f"Error fetching report: {response.status_code} - {response.text}")
        data = response.json()
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        total_engines = sum(stats.values())
        return stats, total_engines

    def upload_and_get_analysis(self, file_path):
        """Upload the file and wait for the analysis to complete."""
        with open(file_path, 'rb') as file:
            files = {"file": (os.path.basename(file_path), file)}
            upload_response = requests.post(
                f"{self.base_url}/files",
                headers=self.headers,
                files=files
            )

        if upload_response.status_code not in [200, 201]:
            raise Exception(f"Upload failed: {upload_response.status_code} - {upload_response.text}")

        analysis_id = upload_response.json()['data']['id']
        print(f"🔍 Uploaded successfully — Analysis ID: {analysis_id}")

        # Poll until analysis completes
        while True:
            analysis_response = requests.get(
                f"{self.base_url}/analyses/{analysis_id}",
                headers=self.headers
            )
            if analysis_response.status_code != 200:
                raise Exception(f"Error fetching analysis: {analysis_response.status_code} - {analysis_response.text}")

            data = analysis_response.json()
            status = data['data']['attributes']['status']
            if status == "completed":
                break
            print("⏳ Waiting for VirusTotal analysis to complete...")
            # time.sleep(2)

        stats = data['data']['attributes']['stats']
        total_engines = sum(stats.values())
        return stats, total_engines

    def scan_file(self, file_path):
        """Scan a file and ensure analysis by at least 15 engines."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        print(f"\n📁 Scanning file: {file_path}")
        file_hash = self.compute_sha256(file_path)

        # Try to get existing report first
        stats, total_engines = self.get_analysis_stats(file_hash)

        if not stats:
            print("⚠️ No existing report found. Uploading for analysis...")
            stats, total_engines = self.upload_and_get_analysis(file_path)

        elif total_engines <= 10:
            print(f"⚠️ Existing report found, but only {total_engines} engines analyzed it. Re-uploading...")
            stats, total_engines = self.upload_and_get_analysis(file_path)
        else:
            print(f"✅ Existing report found from {total_engines} engines.")

        results = {
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'harmless': stats.get('harmless', 0),
            'undetected': stats.get('undetected', 0),
            'total_engines': total_engines,
            'is_malicious': stats.get('malicious', 0) > 0 or stats.get('suspicious', 0) > 0,
        }

        print(f"🧾 Engines used: {total_engines}")
        print(f"Result: {'🚨 Malicious' if results['is_malicious'] else '✅ Clean'}")

        return results



# def main():
#     scanner = VirusTotalScanner()
#     folder_path = Path("mails")

#     if not folder_path.exists():
#         print("❌ Folder 'mails' not found. Make sure emails are saved first.")
#         return

#     file_paths = [f for f in folder_path.glob("*") if f.is_file()]
#     if not file_paths:
#         print("📭 No files found in 'mails' folder to scan.")
#         return

#     summary = []

#     print("\n🚀 Starting VirusTotal scans...")
#     for file_path in file_paths:
#         try:
#             results = scanner.scan_file(str(file_path))
#             status = "🚨 MALICIOUS" if results['is_malicious'] else "✅ CLEAN"
#             print(f"Result for {os.path.basename(file_path)}: {status}")

#             summary.append({
#                 "file": os.path.basename(file_path),
#                 "result": status,
#                 "details": results
#             })

#         except Exception as e:
#             print(f"❌ Error scanning {file_path}: {str(e)}")

#     print("\n📊 === Scan Summary ===")
#     for item in summary:
#         print(f"{item['file']}: {item['result']}:{item['details']}")
#     print("=======================\n")


# if __name__ == "__main__":
#     main()
