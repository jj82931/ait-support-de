import csv
import datetime
import os
import pandas as pd
import pytz

from config import (
    LOG_FILE,
    REPLACEMENT_LOG_FILE,
    ESCALATION_LOG_FILE,
    HIGH_PRIORITY_LOG_FILE,
    AUTH_DB_FILE,
)
from data.db import get_supabase_client


def aest_now():
    """Return current time in AEST (Australia/Sydney)."""
    return datetime.datetime.now(pytz.timezone("Australia/Sydney"))


def init_log_file():
    expected_header = ["Timestamp", "User_Name", "User_Dept", "User_Question", "Category", "Resolved_by_AI"]
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(expected_header)


def log_interaction(question, category, resolved, user_name, user_dept):
    client = get_supabase_client()
    if client:
        client.table("chat_logs").insert({
            "timestamp": aest_now().strftime("%Y-%m-%d %H:%M:%S"),
            "user_name": user_name,
            "user_dept": user_dept,
            "user_question": question,
            "category": category,
            "resolved_by_ai": bool(resolved),
        }).execute()
        return
    init_log_file()
    timestamp = aest_now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, mode='a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, user_name, user_dept, question, category, resolved])


def load_chat_logs():
    client = get_supabase_client()
    if client:
        res = client.table("chat_logs").select("*").execute()
        df = pd.DataFrame(res.data) if res and res.data else pd.DataFrame()
        if df.empty:
            return df
        df.columns = [str(c).strip() for c in df.columns]
        col_map = {
            "timestamp": "Timestamp",
            "user_name": "User_Name",
            "user_dept": "User_Dept",
            "user_question": "User_Question",
            "category": "Category",
            "resolved_by_ai": "Resolved_by_AI",
        }
        df = df.rename(columns={k: v for k, v in col_map.items() if k in df.columns})
        return df
    if not os.path.exists(LOG_FILE):
        return pd.DataFrame()
    try:
        return pd.read_csv(LOG_FILE)
    except Exception:
        return pd.DataFrame()


def init_replacement_log_file():
    expected_header = [
        "Timestamp",
        "User_Name",
        "User_Dept",
        "Device",
        "Reason",
        "Asset_Tag",
        "Checklist",
        "Evidence_Files",
        "Remote_Diagnostics",
        "Status",
        "Review_Status",
        "Admin_Notes",
        "OTP",
        "Ticket_ID",
    ]
    if not os.path.exists(REPLACEMENT_LOG_FILE):
        with open(REPLACEMENT_LOG_FILE, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(expected_header)


def migrate_replacement_log_file():
    if not os.path.exists(REPLACEMENT_LOG_FILE):
        return
    expected_header = [
        "Timestamp",
        "User_Name",
        "User_Dept",
        "Device",
        "Reason",
        "Asset_Tag",
        "Checklist",
        "Evidence_Files",
        "Remote_Diagnostics",
        "Status",
        "Review_Status",
        "Admin_Notes",
        "OTP",
        "Ticket_ID",
    ]
    legacy_header = ["Timestamp", "User_Name", "User_Dept", "Device", "Reason", "OTP", "Status"]
    try:
        with open(REPLACEMENT_LOG_FILE, mode="r", encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)
        if not rows:
            return
        header = rows[0]
        if header == expected_header:
            return
        migrated = [expected_header]
        for row in rows[1:]:
            if not row:
                continue
            if header == legacy_header:
                timestamp, user_name, user_dept, device, reason, otp, status = (row + ["" for _ in range(7)])[:7]
                migrated.append([
                    timestamp, user_name, user_dept, device, reason, "", "", "", "", status, "Pending", "", otp, ""
                ])
            else:
                if len(row) < len(expected_header):
                    row = row + [""] * (len(expected_header) - len(row))
                migrated.append(row[:len(expected_header)])
        with open(REPLACEMENT_LOG_FILE, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerows(migrated)
    except Exception:
        return


def log_replacement_request(user_name, user_dept, device, reason, asset_tag="", evidence_files="", otp_code="", status="Requested", ticket_id=""):
    client = get_supabase_client()
    if client:
        client.table("replacement_requests").insert({
            "timestamp": aest_now().strftime("%Y-%m-%d %H:%M:%S"),
            "user_name": user_name,
            "user_dept": user_dept,
            "device": device,
            "reason": reason,
            "asset_tag": asset_tag,
            "evidence_files": evidence_files,
            "status": status,
            "review_status": "Pending",
            "otp": otp_code,
            "ticket_id": ticket_id,
        }).execute()
        return
    timestamp = aest_now().strftime("%Y-%m-%d %H:%M:%S")
    init_replacement_log_file()
    with open(REPLACEMENT_LOG_FILE, mode='a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            timestamp, user_name, user_dept, device, reason, asset_tag, "", evidence_files, "", status, "Pending", "", otp_code, ticket_id
        ])


def load_replacement_requests():
    client = get_supabase_client()
    if client:
        res = client.table("replacement_requests").select("*").execute()
        df = pd.DataFrame(res.data) if res and res.data else pd.DataFrame()
        if df.empty:
            return df
        df.columns = [str(c).strip() for c in df.columns]
        col_map = {
            "timestamp": "Timestamp",
            "user_name": "User_Name",
            "user_dept": "User_Dept",
            "device": "Device",
            "reason": "Reason",
            "asset_tag": "Asset_Tag",
            "checklist": "Checklist",
            "evidence_files": "Evidence_Files",
            "remote_diagnostics": "Remote_Diagnostics",
            "status": "Status",
            "review_status": "Review_Status",
            "admin_notes": "Admin_Notes",
            "otp": "OTP",
            "ticket_id": "Ticket_ID",
        }
        df = df.rename(columns={k: v for k, v in col_map.items() if k in df.columns})
        if "id" in df.columns:
            df = df.set_index("id", drop=False)
        return df
    if not os.path.exists(REPLACEMENT_LOG_FILE):
        return pd.DataFrame()
    migrate_replacement_log_file()
    try:
        return pd.read_csv(REPLACEMENT_LOG_FILE, engine="python", on_bad_lines="skip")
    except Exception:
        return pd.DataFrame()


def update_replacement_request(index, updates):
    client = get_supabase_client()
    if client:
        col_map = {
            "Timestamp": "timestamp",
            "User_Name": "user_name",
            "User_Dept": "user_dept",
            "Device": "device",
            "Reason": "reason",
            "Asset_Tag": "asset_tag",
            "Checklist": "checklist",
            "Evidence_Files": "evidence_files",
            "Remote_Diagnostics": "remote_diagnostics",
            "Status": "status",
            "Review_Status": "review_status",
            "Admin_Notes": "admin_notes",
            "OTP": "otp",
        }
        mapped = {}
        for key, value in updates.items():
            mapped[col_map.get(key, key)] = value
        client.table("replacement_requests").update(mapped).eq("id", index).execute()
        return True
    df = load_replacement_requests()
    if df.empty or index not in df.index:
        return False
    for key, value in updates.items():
        if key in df.columns:
            df.at[index, key] = value
    df.to_csv(REPLACEMENT_LOG_FILE, index=False)
    return True


def init_escalation_log_file():
    expected_header = [
        "Timestamp",
        "User_Name",
        "User_Dept",
        "User_Question",
        "Escalation_Type",
        "Resolution_Status",
        "Admin_Notes",
        "Unresolved_Reason",
        "Ticket_ID",
    ]
    if not os.path.exists(ESCALATION_LOG_FILE):
        with open(ESCALATION_LOG_FILE, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(expected_header)


def log_escalation_event(user_name, user_dept, question, esc_type, ticket_id=""):
    client = get_supabase_client()
    if client:
        client.table("escalation_reviews").insert({
            "timestamp": aest_now().strftime("%Y-%m-%d %H:%M:%S"),
            "user_name": user_name,
            "user_dept": user_dept,
            "user_question": question,
            "escalation_type": esc_type,
            "resolution_status": "Pending",
            "admin_notes": "",
            "unresolved_reason": "",
            "ticket_id": ticket_id,
        }).execute()
        return
    init_escalation_log_file()
    timestamp = aest_now().strftime("%Y-%m-%d %H:%M:%S")
    with open(ESCALATION_LOG_FILE, mode='a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, user_name, user_dept, question, esc_type, "Pending", "", "", ticket_id])


def load_escalation_reviews():
    client = get_supabase_client()
    if client:
        res = client.table("escalation_reviews").select("*").execute()
        df = pd.DataFrame(res.data) if res and res.data else pd.DataFrame()
        if df.empty:
            return df
        df.columns = [str(c).strip() for c in df.columns]
        col_map = {
            "timestamp": "Timestamp",
            "user_name": "User_Name",
            "user_dept": "User_Dept",
            "user_question": "User_Question",
            "escalation_type": "Escalation_Type",
            "resolution_status": "Resolution_Status",
            "admin_notes": "Admin_Notes",
            "unresolved_reason": "Unresolved_Reason",
            "ticket_id": "Ticket_ID",
        }
        df = df.rename(columns={k: v for k, v in col_map.items() if k in df.columns})
        if "id" in df.columns:
            df = df.set_index("id", drop=False)
        return df
    if not os.path.exists(ESCALATION_LOG_FILE):
        return pd.DataFrame()
    try:
        return pd.read_csv(ESCALATION_LOG_FILE)
    except Exception:
        return pd.DataFrame()


def upsert_escalation_review(index, status, notes, unresolved_reason):
    client = get_supabase_client()
    if client:
        client.table("escalation_reviews").update({
            "resolution_status": status,
            "admin_notes": notes,
            "unresolved_reason": unresolved_reason,
        }).eq("id", index).execute()
        return True
    df = load_escalation_reviews()
    if df.empty or index not in df.index:
        return False
    df.at[index, "Resolution_Status"] = status
    df.at[index, "Admin_Notes"] = notes
    df.at[index, "Unresolved_Reason"] = unresolved_reason
    df.to_csv(ESCALATION_LOG_FILE, index=False)
    return True


def init_high_priority_log_file():
    expected_header = ["Timestamp", "User_Name", "User_Dept", "Issue_Summary", "Status", "Admin_Notes", "Ticket_ID"]
    if not os.path.exists(HIGH_PRIORITY_LOG_FILE):
        with open(HIGH_PRIORITY_LOG_FILE, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(expected_header)


def log_high_priority_ticket(user_name, user_dept, issue_summary, ticket_id=""):
    client = get_supabase_client()
    if client:
        client.table("high_priority_tickets").insert({
            "timestamp": aest_now().strftime("%Y-%m-%d %H:%M:%S"),
            "user_name": user_name,
            "user_dept": user_dept,
            "issue_summary": issue_summary,
            "status": "Pending",
            "admin_notes": "",
            "ticket_id": ticket_id,
        }).execute()
        return
    init_high_priority_log_file()
    timestamp = aest_now().strftime("%Y-%m-%d %H:%M:%S")
    with open(HIGH_PRIORITY_LOG_FILE, mode='a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, user_name, user_dept, issue_summary, "Pending", "", ticket_id])


def load_high_priority_tickets():
    client = get_supabase_client()
    if client:
        res = client.table("high_priority_tickets").select("*").execute()
        df = pd.DataFrame(res.data) if res and res.data else pd.DataFrame()
        if df.empty:
            return df
        df.columns = [str(c).strip() for c in df.columns]
        col_map = {
            "timestamp": "Timestamp",
            "user_name": "User_Name",
            "user_dept": "User_Dept",
            "issue_summary": "Issue_Summary",
            "status": "Status",
            "admin_notes": "Admin_Notes",
            "ticket_id": "Ticket_ID",
        }
        df = df.rename(columns={k: v for k, v in col_map.items() if k in df.columns})
        if "id" in df.columns:
            df = df.set_index("id", drop=False)
        return df
    if not os.path.exists(HIGH_PRIORITY_LOG_FILE):
        return pd.DataFrame()
    try:
        return pd.read_csv(HIGH_PRIORITY_LOG_FILE)
    except Exception:
        return pd.DataFrame()


def update_high_priority_ticket(index, status, notes):
    client = get_supabase_client()
    if client:
        client.table("high_priority_tickets").update({"status": status, "admin_notes": notes}).eq("id", index).execute()
        return True
    df = load_high_priority_tickets()
    if df.empty or index not in df.index:
        return False
    df.at[index, "Status"] = status
    df.at[index, "Admin_Notes"] = notes
    df.to_csv(HIGH_PRIORITY_LOG_FILE, index=False)
    return True

def find_ticket_status(ticket_id):
    """Find ticket status across supported tables."""
    if not ticket_id:
        return None
    client = get_supabase_client()
    if client:
        tables = [
            ("replacement_requests", "status", "admin_notes", None),
            ("escalation_reviews", "resolution_status", "admin_notes", "unresolved_reason"),
            ("high_priority_tickets", "status", "admin_notes", None),
        ]
        for table, status_field, notes_field, unresolved_field in tables:
            res = client.table(table).select("*").eq("ticket_id", ticket_id).limit(1).execute()
            if res and res.data:
                row = res.data[0]
                return {
                    "table": table,
                    "status": row.get(status_field),
                    "admin_notes": row.get(notes_field, ""),
                    "unresolved_reason": row.get(unresolved_field, "") if unresolved_field else "",
                }
        return None
    # CSV fallback
    for df, status_col, notes_col, unresolved_col, table in [
        (load_replacement_requests(), "Status", "Admin_Notes", None, "replacement_requests"),
        (load_escalation_reviews(), "Resolution_Status", "Admin_Notes", "Unresolved_Reason", "escalation_reviews"),
        (load_high_priority_tickets(), "Status", "Admin_Notes", None, "high_priority_tickets"),
    ]:
        if df is None or df.empty:
            continue
        if "Ticket_ID" not in df.columns:
            continue
        match = df[df["Ticket_ID"] == ticket_id]
        if not match.empty:
            row = match.iloc[0]
            return {
                "table": table,
                "status": row.get(status_col),
                "admin_notes": row.get(notes_col, ""),
                "unresolved_reason": row.get(unresolved_col, "") if unresolved_col else "",
            }
    return None

def load_authorized_users():
    client = get_supabase_client()
    if client:
        res = client.table("authorized_users").select("*").execute()
        df = pd.DataFrame(res.data) if res and res.data else pd.DataFrame()
        if df.empty:
            return df
        df.columns = [str(c).strip() for c in df.columns]
        col_map = {
            "user_name": "User_Name",
            "user_dept": "User_Dept",
            "role": "Role",
        }
        df = df.rename(columns={k: v for k, v in col_map.items() if k in df.columns})
        return df
    if not os.path.exists(AUTH_DB_FILE):
        return None
    try:
        df = pd.read_csv(AUTH_DB_FILE)
        if "User_Name" not in df.columns or "User_Dept" not in df.columns:
            return None
        df["User_Name"] = df["User_Name"].astype(str).str.strip().str.lower()
        df["User_Dept"] = df["User_Dept"].astype(str).str.strip().str.lower()
        if "Role" not in df.columns:
            df["Role"] = "user"
        else:
            df["Role"] = df["Role"].fillna("user").astype(str).str.strip().str.lower()
        return df
    except Exception:
        return None


def authorize_user(name, dept):
    df = load_authorized_users()
    if df is None or df.empty:
        return None
    # Normalize column names for both CSV and Supabase sources
    df.columns = [str(c).strip() for c in df.columns]
    if "User_Name" not in df.columns and "user_name" in df.columns:
        df = df.rename(columns={"user_name": "User_Name"})
    if "User_Dept" not in df.columns and "user_dept" in df.columns:
        df = df.rename(columns={"user_dept": "User_Dept"})
    if "Role" not in df.columns and "role" in df.columns:
        df = df.rename(columns={"role": "Role"})
    name_key = name.strip().lower()
    dept_key = dept.strip().lower()
    if not name_key or not dept_key:
        return None
    df["_name_norm"] = df["User_Name"].astype(str).str.strip().str.lower()
    df["_dept_norm"] = df["User_Dept"].astype(str).str.strip().str.lower()
    match = df[(df["_name_norm"] == name_key) & (df["_dept_norm"] == dept_key)]
    if match.empty:
        return None
    role = match.iloc[0].get("Role", "user")
    return role or "user"
