INDEX_PATH = "vectorstore/faiss_index"
LOG_FILE = "chat_logs.csv"
REPLACEMENT_LOG_FILE = "replacement_requests.csv"
ESCALATION_LOG_FILE = "escalation_reviews.csv"
HIGH_PRIORITY_LOG_FILE = "high_priority_tickets.csv"
AUTH_DB_FILE = "authorized_users.csv"
REPLACEMENT_EVIDENCE_DIR = "replacement_evidence"

REPLACEMENT_KEYWORDS = [
    "broken screen",
    "cracked screen",
    "dead battery",
    "battery won't charge",
    "won't power on",
    "not powering on",
    "liquid damage",
    "water damage",
    "snapped",
    "physically broken",
]

CRITICAL_KEYWORDS = [
    "smoke",
    "fire",
    "burning",
    "electrical smell",
    "sparks",
]

DEVICE_KEYWORDS = {
    "Zebra Scanner": ["zebra", "scanner"],
    "Label Printer": ["printer", "label printer"],
    "Handheld Tablet": ["tablet", "handheld"],
    "RFID Reader": ["rfid", "reader"],
    "Rugged Laptop": ["rugged laptop", "laptop"],
}

DEMO_HIGH_PRIORITY_URL = "https://example.com/high-priority-ticket-demo"

MAX_EVIDENCE_FILES = 3
MAX_EVIDENCE_MB = 5
MAX_EVIDENCE_TOTAL_MB = 10

SUPABASE_EVIDENCE_BUCKET = "replacement-evidence"

TICKET_PREFIXES = {
    "replacement": "RPL",
    "escalation": "ESC",
    "high_priority": "HP",
}

TICKET_DEDUPE_MINUTES = 30
