from pymongo import MongoClient

MONGO_URI = "mongodb://localhost:27017"

client = MongoClient(MONGO_URI)

db = client["test-security-database"]
scan_history = db["scan_history"]