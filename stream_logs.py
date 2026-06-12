import os
import paramiko
import requests
from dotenv import load_dotenv

# Load your setup.env
load_dotenv(dotenv_path="setup.env")

# CONFIGURATION
# Replace with your Ubuntu machine's actual IP
UBUNTU_URL = "http://172.21.131.173:8080/ingest"

def start_bridge():
    host = os.getenv("SERVER_IP")
    user = os.getenv("SERVER_USER")
    pwd = os.getenv("SERVER_PASSWORD")
    log_file = os.getenv("LOG_PATH")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        print(f"--- Connecting to Critical System via VPN ({host}) ---")
        client.connect(hostname=host, username=user, password=pwd, timeout=15)
        
        print("--- Connection Successful. Tailing Logs... ---")
        stdin, stdout, stderr = client.exec_command(f"tail -f {log_file}")

        for line in iter(stdout.readline, ""):
            log_line = line.strip()
            if log_line:
                # Push the log line to Ubuntu
                try:
                    requests.post(UBUNTU_URL, data=log_line, timeout=2)
                    print(f"Forwarded: {log_line[:50]}...")
                except Exception as e:
                    print(f"Failed to push to Ubuntu: {e}")

    except Exception as e:
        print(f"SSH Error: {e}")
    finally:
        client.close()
        print("Bridge closed.")

if __name__ == "__main__":
    start_bridge()
