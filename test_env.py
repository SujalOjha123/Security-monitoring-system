from dotenv import load_dotenv
import os

load_dotenv("config/setup.env")

print("HOST:", os.getenv("SERVER_HOST"))
print("USER:", os.getenv("SERVER_USER"))
print("LOG:", os.getenv("LOG_PATH"))