import streamlit as st
import os
import tempfile
import datetime
import json
import random
import pytz
import pandas as pd
import urllib.parse
from dotenv import load_dotenv

from config import (
    INDEX_PATH,
    REPLACEMENT_EVIDENCE_DIR,
    REPLACEMENT_KEYWORDS,
    CRITICAL_KEYWORDS,
    DEVICE_KEYWORDS,
    DEMO_HIGH_PRIORITY_URL,
    MAX_EVIDENCE_FILES,
    MAX_EVIDENCE_MB,
    MAX_EVIDENCE_TOTAL_MB,
    SUPABASE_EVIDENCE_BUCKET,
    TICKET_PREFIXES,
    TICKET_DEDUPE_MINUTES,
)
from data.db import get_supabase_client
from data.repositories import (
    log_interaction,
    load_chat_logs,
    log_replacement_request,
    load_replacement_requests,
    update_replacement_request,
    log_escalation_event,
    load_escalation_reviews,
    upsert_escalation_review,
    log_high_priority_ticket,
    load_high_priority_tickets,
    update_high_priority_ticket,
    load_authorized_users,
    authorize_user,
    find_ticket_status,
)

from langchain_google_genai import ChatGoogleGenerativeAI, GoogleGenerativeAIEmbeddings
from langchain_community.vectorstores import FAISS
from langchain_text_splitters import RecursiveCharacterTextSplitter
try:
    from langchain.chains import create_retrieval_chain
    from langchain.chains.combine_documents import create_stuff_documents_chain
except ModuleNotFoundError:
    from langchain_classic.chains import create_retrieval_chain
    from langchain_classic.chains.combine_documents import create_stuff_documents_chain
from langchain_core.prompts import ChatPromptTemplate
from langchain_community.document_loaders import PyPDFLoader, TextLoader
import streamlit.components.v1 as components

# Load environment variables
load_dotenv()

AEST_TZ = pytz.timezone("Australia/Sydney")

def aest_now():
    """Return current time in AEST (Australia/Sydney)."""
    return datetime.datetime.now(AEST_TZ)

def aest_now_naive():
    """Return naive datetime in AEST for cache comparisons."""
    return aest_now().replace(tzinfo=None)

def classify_topic(question, llm):
    """Classify the user question into predefined categories."""
    categories = ["Hardware (Scanner/Printer)", "Network/VPN", "SAP/Software", "Account/Auth", "Other"]
    prompt = f"Classify this IT support question into exactly one of these categories: {categories}. Return ONLY the category name.\n\nQuestion: {question}"
    try:
        response = llm.invoke(prompt)
        category = response.content.strip()
        # Validate if returned category is in the list
        for cat in categories:
            if cat.lower() in category.lower():
                return cat
        return "Other"
    except:
        return "Other"

def detect_device(text):
    """Infer a device name from user text."""
    lowered = text.lower()
    for device, keywords in DEVICE_KEYWORDS.items():
        for keyword in keywords:
            if keyword in lowered:
                return device
    return "Warehouse Device"

def build_recent_context(messages, limit=6):
    """Build a compact recent chat context."""
    recent = messages[-limit:]
    lines = []
    for msg in recent:
        role = msg.get("role", "user")
        content = msg.get("content", "").strip()
        if not content:
            continue
        label = "User" if role == "user" else "Assistant"
        lines.append(f"{label}: {content}")
    return "\n".join(lines)

def update_conversation_summary(messages, llm):
    """Update conversation summary intermittently to limit token usage."""
    recent_context = build_recent_context(messages, limit=6)
    if not recent_context:
        return ""
    prompt = (
        "Summarize the conversation so far in 1-2 concise sentences, focusing on the current issue and any constraints.\n\n"
        f"Conversation:\n{recent_context}"
    )
    try:
        return llm.invoke(prompt).content.strip()
    except Exception:
        return ""

def summarize_issue_for_email(messages, llm, fallback_prompt):
    """Summarize the issue for an IT support email draft."""
    recent_context = build_recent_context(messages, limit=8)
    if not recent_context:
        return fallback_prompt
    prompt = (
        "Summarize the user's issue in 2-3 concise sentences for an IT support ticket. "
        "Include key symptoms, environment details, and any troubleshooting already attempted. "
        "Avoid fluff and keep it clear.\n\n"
        f"Conversation:\n{recent_context}"
    )
    try:
        summary = llm.invoke(prompt).content.strip()
        return summary or fallback_prompt
    except Exception:
        return fallback_prompt

def parse_shift_summary(summary_text):
    """Extract major issues and pending items from summary text."""
    major = "None"
    pending = "None"
    if not summary_text:
        return major, pending
    for line in summary_text.splitlines():
        line = line.strip()
        if line.lower().startswith("- major issues:"):
            major = line.split(":", 1)[1].strip() or "None"
        elif line.lower().startswith("- pending items:"):
            pending = line.split(":", 1)[1].strip() or "None"
    return major, pending

def parse_checklist(checklist_text):
    """Parse checklist JSON stored in the log."""
    if not checklist_text or not isinstance(checklist_text, str):
        return {}
    try:
        return json.loads(checklist_text)
    except Exception:
        return {}

def validate_evidence_files(files):
    """Validate evidence upload limits for free tier safety."""
    if not files:
        return True, ""
    if len(files) > MAX_EVIDENCE_FILES:
        return False, f"Max {MAX_EVIDENCE_FILES} files allowed."
    total_mb = 0.0
    for f in files:
        size = getattr(f, "size", None)
        if size is None:
            continue
        size_mb = size / (1024 * 1024)
        total_mb += size_mb
        if size_mb > MAX_EVIDENCE_MB:
            return False, f"Each file must be <= {MAX_EVIDENCE_MB} MB."
    if total_mb > MAX_EVIDENCE_TOTAL_MB:
        return False, f"Total upload must be <= {MAX_EVIDENCE_TOTAL_MB} MB."
    return True, ""

def generate_ticket_id(kind):
    """Generate a short ticket id."""
    prefix = TICKET_PREFIXES.get(kind, "TCK")
    stamp = aest_now().strftime("%Y%m%d")
    rand = str(random.randint(1000, 9999))
    return f"{prefix}-{stamp}-{rand}"

def is_ticket_id_request(text):
    """Detect when user asks for a previous ticket number."""
    lowered = (text or "").lower()
    triggers = [
        "forgot the previous ticket number",
        "forgot the ticket number",
        "forgot ticket number",
        "ticket id",
        "previous ticket",
        "ticket number",
    ]
    return any(trigger in lowered for trigger in triggers)

def get_or_create_ticket(kind, issue_context, prompt_text=""):
    """Return existing ticket id within dedupe window or create a new one."""
    issue_key = f"{kind}:{issue_context.strip().lower()}"
    cache = st.session_state.ticket_cache
    now = aest_now_naive()

    def age_minutes(ts):
        if not isinstance(ts, datetime.datetime):
            return None
        if ts.tzinfo is not None:
            ts = ts.astimezone(AEST_TZ).replace(tzinfo=None)
        return (now - ts).total_seconds() / 60.0

    # If user asks for ticket number, reuse the most recent ticket of this kind.
    if is_ticket_id_request(prompt_text):
        recent = cache.get(f"{kind}:_last")
        if recent:
            minutes = age_minutes(recent["ts"])
            if minutes is not None and minutes <= TICKET_DEDUPE_MINUTES:
                return recent["ticket_id"], False

    entry = cache.get(issue_key)
    if entry:
        minutes = age_minutes(entry["ts"])
        if minutes is not None and minutes <= TICKET_DEDUPE_MINUTES:
            return entry["ticket_id"], False

    # Fallback: reuse last ticket of the same kind within window
    recent = cache.get(f"{kind}:_last")
    if recent:
        minutes = age_minutes(recent["ts"])
        if minutes is not None and minutes <= TICKET_DEDUPE_MINUTES:
            return recent["ticket_id"], False

    ticket_id = generate_ticket_id(kind)
    cache[issue_key] = {"ticket_id": ticket_id, "ts": now}
    cache[f"{kind}:_last"] = {"ticket_id": ticket_id, "ts": now}
    return ticket_id, True

def save_evidence_files(files, ticket_id):
    """Save evidence files and return a list of saved filenames."""
    if not files:
        return []
    client = get_supabase_client()
    if client is None:
        os.makedirs(REPLACEMENT_EVIDENCE_DIR, exist_ok=True)
    saved = []
    timestamp = aest_now().strftime("%Y%m%d-%H%M%S")
    for f in files:
        safe_name = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in f.name)
        safe_ticket = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in str(ticket_id))
        filename = f"{safe_ticket}_{timestamp}_{safe_name}"
        if client is None:
            path = os.path.join(REPLACEMENT_EVIDENCE_DIR, filename)
            with open(path, "wb") as out_f:
                out_f.write(f.getbuffer())
            saved.append(filename)
        else:
            file_path = f"{safe_ticket}/{filename}"
            content = f.getbuffer().tobytes()
            client.storage.from_(SUPABASE_EVIDENCE_BUCKET).upload(
                file_path,
                content,
                file_options={"content-type": f.type or "application/octet-stream"},
            )
            public_url = client.storage.from_(SUPABASE_EVIDENCE_BUCKET).get_public_url(file_path)
            saved.append(public_url)
    return saved

def is_replacement_case(prompt_text, response_text):
    """Detect hardware failure that requires replacement."""
    combined = f"{prompt_text}\n{response_text}".lower()
    if "[esc_replace]" in combined:
        return True
    return any(keyword in combined for keyword in REPLACEMENT_KEYWORDS)

def is_critical_incident_llm(prompt_text, summary_text, llm):
    """Use LLM to classify safety-critical incidents."""
    prompt = (
        "Determine if the user's LATEST message indicates a HIGH-PRIORITY incident that requires immediate escalation. "
        "Base your decision primarily on the latest message. If the latest message is a sign-off, thanks, or unrelated, "
        "respond NO even if earlier context was critical. Return ONLY one word: YES or NO.\n\n"
        f"Latest message:\n{prompt_text}\n\n"
        f"Conversation summary:\n{summary_text or 'None'}"
    )
    try:
        result = llm.invoke(prompt).content.strip().upper()
        return result == "YES"
    except Exception:
        return False

def is_escalation_response(response_text):
    """Detect escalation intent when the model forgets to include tags."""
    text = (response_text or "").lower()
    triggers = [
        "escalate",
        "escalated",
        "level 2",
        "level-2",
        "specialist",
        "advanced tools",
        "further analysis",
    ]
    return any(trigger in text for trigger in triggers)

def ensure_escalation_tag(response_text, llm):
    """Ensure the response ends with a required escalation tag."""
    tags = ["[ESC_VIDEO]", "[ESC_REPLACE]", "[ESC_FAIL]", "[ESC_NONE]"]
    if any(tag in response_text for tag in tags):
        return response_text
    prompt = (
        "Append exactly one escalation tag to the end of the response. "
        "Choose one of: [ESC_VIDEO], [ESC_REPLACE], [ESC_FAIL], [ESC_NONE]. "
        "Return only the original response with the tag appended.\n\n"
        f"Response:\n{response_text}"
    )
    try:
        tagged = llm.invoke(prompt).content.strip()
        return tagged if any(tag in tagged for tag in tags) else response_text
    except Exception:
        return response_text

@st.dialog(" Admin Access", width="large")
def admin_login_dialog():
    """Centered dialog for admin authentication and dashboard."""
    if "admin_authenticated" not in st.session_state:
        st.session_state.admin_authenticated = False
        
    if not st.session_state.admin_authenticated:
        st.write("Please authenticate to access the dashboard.")
        password = st.text_input("Admin Password", type="password")
        if st.button("Login", use_container_width=True):
            if password == "admin123":
                st.session_state.admin_authenticated = True
                st.rerun()
            else:
                st.error("Access Denied")
    else:
        show_admin_dashboard()
        st.divider()
        if st.button("Logout Admin", use_container_width=True):
            st.session_state.admin_authenticated = False
            st.rerun()

def is_aest_business_hours():
    """Check if current time is Mon-Fri, 08:00 - 18:00 AEST."""
    aest = pytz.timezone('Australia/Sydney')
    now = datetime.datetime.now(aest)
    if 0 <= now.weekday() <= 4:  # Mon-Fri
        if 8 <= now.hour < 18:
            return True
    return False

def load_vector_store():
    """Load the persistent vector store from disk."""
    if os.path.exists(INDEX_PATH):
        try:
            embeddings = GoogleGenerativeAIEmbeddings(model="models/embedding-001")
            return FAISS.load_local(INDEX_PATH, embeddings, allow_dangerous_deserialization=True)
        except Exception as e:
            print(f"Error loading index: {e}")
            return None
    default_manual = os.path.join("doc", "manual.pdf")
    if os.path.exists(default_manual):
        try:
            loader = PyPDFLoader(default_manual)
            documents = loader.load()
            text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=150)
            docs = text_splitter.split_documents(documents)
            embeddings = GoogleGenerativeAIEmbeddings(model="models/embedding-001")
            vector_store = FAISS.from_documents(docs, embeddings)
            vector_store.save_local(INDEX_PATH)
            metadata_dir = os.path.dirname(INDEX_PATH)
            if not os.path.exists(metadata_dir):
                os.makedirs(metadata_dir)
            metadata_path = os.path.join(metadata_dir, "source_files.txt")
            with open(metadata_path, "a", encoding="utf-8") as f:
                f.write("manual.pdf\n")
            return vector_store
        except Exception as e:
            print(f"Error building index from manual: {e}")
            return None
    return None

def process_document(uploaded_file):
    """Process document and save to persistent storage."""
    try:
        suffix = f".{uploaded_file.name.split('.')[-1]}"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_file:
            tmp_file.write(uploaded_file.getvalue())
            tmp_path = tmp_file.name

        if uploaded_file.name.lower().endswith(".pdf"):
            loader = PyPDFLoader(tmp_path)
        else:
            loader = TextLoader(tmp_path)
            
        documents = loader.load()
        os.remove(tmp_path)

        text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=150)
        docs = text_splitter.split_documents(documents)

        embeddings = GoogleGenerativeAIEmbeddings(model="models/embedding-001")
        vector_store = FAISS.from_documents(docs, embeddings)
        
        vector_store.save_local(INDEX_PATH)
        
        # Track the filename
        metadata_dir = os.path.dirname(INDEX_PATH)
        if not os.path.exists(metadata_dir):
            os.makedirs(metadata_dir)
        metadata_path = os.path.join(metadata_dir, "source_files.txt")
        with open(metadata_path, "a", encoding="utf-8") as f:
            f.write(f"{uploaded_file.name}\n")
            
        return vector_store
    except Exception as e:
        st.error(f"Error processing document: {e}")
        return None

def show_admin_dashboard():
    """Display the admin dashboard inside the popover/dialog."""
    if st.session_state.get("user_role") != "admin":
        st.error("Admin access only.")
        return
    st.subheader(" Admin Insight Dashboard")
    
    # Dashboard Tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        ["High Priority", "Analytics", "Knowledge Management", "Replacement Requests", "Escalation Reviews"]
    )

    with tab1:
        st.subheader("High Priority Tickets")
        df_hp = load_high_priority_tickets()
        if df_hp.empty:
            st.info("No high-priority tickets logged yet.")
        else:
            st.write("**Pending First**")
            pending = df_hp[df_hp["Status"] == "Pending"]
            resolved = df_hp[df_hp["Status"] != "Pending"]
            if not pending.empty:
                st.dataframe(pending, use_container_width=True)
            if not resolved.empty:
                st.dataframe(resolved, use_container_width=True)
            st.divider()
            st.write("**Update Ticket**")
            options = list(df_hp.index)
            def _hp_label(i):
                row = df_hp.loc[i]
                return f"{i} | {row.get('Timestamp', '')} | {row.get('User_Name', '')} | {row.get('Status', '')}"
            selected_index = st.selectbox("Select Ticket", options, format_func=_hp_label, key="hp_select")
            row = df_hp.loc[selected_index]
            status_options = ["Pending", "Resolved", "Unresolved"]
            current_status = row.get("Status", "Pending")
            status_index = status_options.index(current_status) if current_status in status_options else 0
            status = st.selectbox("Status", status_options, index=status_index, key="hp_status")
            notes_val = "" if pd.isna(row.get("Admin_Notes", "")) else str(row.get("Admin_Notes", ""))
            notes = st.text_area("Admin Notes", value=notes_val, key="hp_notes")
            if st.button("Save High Priority Ticket", key="hp_save", use_container_width=True):
                if update_high_priority_ticket(selected_index, status, notes.strip()):
                    st.success("High priority ticket updated.")
                else:
                    st.error("Unable to update ticket.")

    with tab2:
        try:
            df = load_chat_logs()
            if not df.empty:
                st.write("**Top Recurring Issues (Real-time)**")
                category_counts = df['Category'].value_counts()
                st.bar_chart(category_counts)
                
                col1, col2 = st.columns(2)
                with col1:
                    resolved_count = df[df['Resolved_by_AI'] == True].shape[0]
                    money_saved = resolved_count * 15
                    st.metric("Total Cost Saved", f"${money_saved}", delta=f"Based on {resolved_count} resolutions")
                with col2:
                    st.metric("Total Inquiries", len(df))
            else:
                st.info("Log file is empty.")
        except Exception as e:
            st.error(f"Error reading logs: {e}. Try deleting chat logs to reset.")

    with tab3:
        st.subheader("Manage IT Manuals")
        uploaded_file = st.file_uploader("Upload New Manual (PDF/TXT)", type=["pdf", "txt"])
        if uploaded_file and st.button("Index & Save Knowledge Base"):
            with st.spinner("Processing..."):
                st.session_state.vector_store = process_document(uploaded_file)
                if st.session_state.vector_store:
                    st.success(f"'{uploaded_file.name}' has been indexed!")
        
        st.divider()
        st.write("**Current Active Manuals**")
        metadata_path = os.path.join(os.path.dirname(INDEX_PATH), "source_files.txt")
        if os.path.exists(metadata_path):
            with open(metadata_path, "r", encoding="utf-8") as f:
                files = list(set(f.read().splitlines())) # Show unique files
                for f_name in files:
                    st.text(f" {f_name}")
        else:
            st.warning("No manuals indexed yet.")

    with tab4:
        st.subheader("Replacement Requests")
        df = load_replacement_requests()
        if df.empty:
            st.info("No replacement requests logged yet.")
        else:
            st.write("**Pending First**")
            pending = df[df["Status"].isin(["Requested", "Pending", "Under Review"])]
            resolved = df[~df["Status"].isin(["Requested", "Pending", "Under Review"])]
            if not pending.empty:
                st.dataframe(pending, use_container_width=True)
            if not resolved.empty:
                st.dataframe(resolved, use_container_width=True)
            st.divider()
            st.write("**Review Workflow**")
            options = list(df.index)
            def _rep_label(i):
                row = df.loc[i]
                return f"{i} | {row.get('Timestamp', '')} | {row.get('User_Name', '')} | {row.get('Status', '')}"
            selected_index = st.selectbox("Select Request", options, format_func=_rep_label, key="rep_select")
            row = df.loc[selected_index]

            checklist_items = {
                "Power cycle attempted": False,
                "Cables and ports checked": False,
                "Device cleaned/inspected": False,
                "Firmware updated": False,
                "Self-test run": False,
                "Known-good swap tested": False,
            }
            existing_checklist = parse_checklist(row.get("Checklist", ""))
            for k in checklist_items:
                checklist_items[k] = bool(existing_checklist.get(k, False))

            asset_tag = st.text_input(
                "Asset Tag",
                value=str(row.get("Asset_Tag", "")),
                key=f"rep_asset_tag_{selected_index}",
            )
            asset_verified = st.checkbox(
                "Asset tag verified against inventory",
                value=bool(existing_checklist.get("Asset Tag Verified", False)),
                key=f"rep_asset_verified_{selected_index}",
            )

            st.write("**Verification Checklist**")
            for key in list(checklist_items.keys()):
                checklist_items[key] = st.checkbox(
                    key,
                    value=checklist_items[key],
                    key=f"rep_check_{selected_index}_{key}",
                )

            st.write("**Evidence (required before approval)**")
            uploaded = st.file_uploader(
                "Upload photos/logs",
                type=["png", "jpg", "jpeg", "pdf", "txt"],
                accept_multiple_files=True,
                key=f"rep_evidence_{selected_index}",
            )
            st.caption(
                f"Limits: {MAX_EVIDENCE_FILES} files, {MAX_EVIDENCE_MB} MB each, "
                f"{MAX_EVIDENCE_TOTAL_MB} MB total."
            )
            evidence_list = []
            existing_evidence = str(row.get("Evidence_Files", "")).strip()
            if existing_evidence:
                evidence_list.extend([x for x in existing_evidence.split("|") if x])
            if evidence_list:
                st.caption("Existing evidence: " + ", ".join(evidence_list))
                for filename in evidence_list:
                    if filename.startswith("http"):
                        st.link_button(
                            f"Open Evidence {filename.split('/')[-1]}",
                            filename,
                            use_container_width=True,
                        )
                    else:
                        file_path = os.path.join(REPLACEMENT_EVIDENCE_DIR, filename)
                        if os.path.exists(file_path):
                            with open(file_path, "rb") as f:
                                st.download_button(
                                    label=f"Download {filename}",
                                    data=f,
                                    file_name=filename,
                                    use_container_width=True,
                                    key=f"rep_download_{selected_index}_{filename}",
                                )

            if uploaded:
                if st.button("Save Evidence", use_container_width=True, key=f"rep_save_evidence_{selected_index}"):
                    ok, msg = validate_evidence_files(uploaded)
                    if not ok:
                        st.error(msg)
                    else:
                        saved_files = save_evidence_files(uploaded, str(selected_index))
                        evidence_list.extend(saved_files)
                        updates = {
                            "Evidence_Files": "|".join(evidence_list),
                        }
                        if update_replacement_request(selected_index, updates):
                            st.success("Evidence saved.")

            remote_diag = st.text_area(
                "Remote diagnostics / observations",
                value=str(row.get("Remote_Diagnostics", "")),
                key=f"rep_remote_diag_{selected_index}",
            )
            admin_notes = st.text_area(
                "Admin notes",
                value=str(row.get("Admin_Notes", "")),
                key=f"rep_admin_notes_{selected_index}",
            )

            status_options = ["Requested", "Pending", "Under Review", "Approved", "Denied", "Cancelled"]
            review_status_options = ["Pending", "Reviewed"]
            status = st.selectbox(
                "Status",
                status_options,
                index=status_options.index(row.get("Status", "Requested")) if row.get("Status", "Requested") in status_options else 0,
                key=f"rep_status_{selected_index}",
            )
            review_status = st.selectbox(
                "Review Status",
                review_status_options,
                index=review_status_options.index(row.get("Review_Status", "Pending")) if row.get("Review_Status", "Pending") in review_status_options else 0,
                key=f"rep_review_status_{selected_index}",
            )

            # Cooldown warning (30 days)
            cooldown_days = 30
            recent_matches = df[
                (df.index != selected_index) &
                (df["Status"] == "Approved") &
                (
                    (df["User_Name"] == row.get("User_Name")) |
                    ((df["Device"] == row.get("Device")) & (df["User_Dept"] == row.get("User_Dept"))) |
                    ((df["Asset_Tag"] == asset_tag) & (asset_tag != ""))
                )
            ]
            if not recent_matches.empty:
                st.warning("Recent approved replacement found for this user/device/asset. Review carefully.")
                override_cooldown = st.checkbox(
                    "Override cooldown",
                    value=False,
                    key=f"rep_override_cooldown_{selected_index}",
                )
            else:
                override_cooldown = True

            checklist_items["Asset Tag Verified"] = asset_verified

            col_a, col_b, col_c = st.columns(3)
            with col_a:
                if st.button("Mark Reviewed", use_container_width=True, key=f"rep_mark_reviewed_{selected_index}"):
                    ok, msg = validate_evidence_files(uploaded)
                    if not ok:
                        st.error(msg)
                    else:
                        evidence_files = evidence_list + (save_evidence_files(uploaded, str(selected_index)) if uploaded else [])
                        updates = {
                            "Checklist": json.dumps(checklist_items),
                            "Asset_Tag": asset_tag.strip(),
                            "Evidence_Files": "|".join(evidence_files),
                            "Remote_Diagnostics": remote_diag.strip(),
                            "Admin_Notes": admin_notes.strip(),
                            "Review_Status": "Reviewed",
                        }
                        if update_replacement_request(selected_index, updates):
                            st.success("Review marked as completed.")
            with col_b:
                if st.button("Approve Replacement", use_container_width=True, key=f"rep_approve_{selected_index}"):
                    missing_checks = [k for k, v in checklist_items.items() if not v]
                    if not asset_tag.strip():
                        st.error("Asset tag is required before approval.")
                    elif missing_checks:
                        st.error("Complete all checklist items before approval.")
                    elif not evidence_list and not uploaded:
                        st.error("Evidence is required before approval.")
                    elif review_status != "Reviewed":
                        st.error("Mark the review as completed before approval.")
                    elif not override_cooldown:
                        st.error("Cooldown override required to approve this request.")
                    else:
                        ok, msg = validate_evidence_files(uploaded)
                        if not ok:
                            st.error(msg)
                        else:
                            existing_otp = str(row.get("OTP", "")).strip()
                            otp_code = existing_otp if existing_otp else str(random.randint(1000, 9999))
                            evidence_files = evidence_list + (save_evidence_files(uploaded, str(selected_index)) if uploaded else [])
                            updates = {
                                "Checklist": json.dumps(checklist_items),
                                "Asset_Tag": asset_tag.strip(),
                                "Evidence_Files": "|".join(evidence_files),
                                "Remote_Diagnostics": remote_diag.strip(),
                                "Admin_Notes": admin_notes.strip(),
                                "Status": "Approved",
                                "Review_Status": "Reviewed",
                                "OTP": otp_code,
                            }
                            if update_replacement_request(selected_index, updates):
                                st.success(f"Replacement approved. OTP: {otp_code}")
            with col_c:
                if st.button("Deny Request", use_container_width=True, key=f"rep_deny_{selected_index}"):
                    if not admin_notes.strip():
                        st.error("Add admin notes explaining why the request is denied.")
                    else:
                        ok, msg = validate_evidence_files(uploaded)
                        if not ok:
                            st.error(msg)
                        else:
                            evidence_files = evidence_list + (save_evidence_files(uploaded, str(selected_index)) if uploaded else [])
                            updates = {
                                "Checklist": json.dumps(checklist_items),
                                "Asset_Tag": asset_tag.strip(),
                                "Evidence_Files": "|".join(evidence_files),
                                "Remote_Diagnostics": remote_diag.strip(),
                                "Admin_Notes": admin_notes.strip(),
                                "Status": "Denied",
                            }
                            if update_replacement_request(selected_index, updates):
                                st.success("Replacement request denied.")

    with tab5:
        st.subheader("Escalation Reviews")
        df = load_escalation_reviews()
        if df.empty:
            st.info("No escalations logged yet.")
        else:
            st.write("**Recent Escalations**")
            st.dataframe(df.tail(20), use_container_width=True)
            st.divider()
            st.write("**Update Resolution**")
            options = list(df.index)
            def _label(i):
                row = df.loc[i]
                return f"{i} | {row.get('Timestamp', '')} | {row.get('User_Name', '')} | {row.get('Escalation_Type', '')}"
            selected_index = st.selectbox("Select Ticket", options, format_func=_label, key="esc_review_select")
            row = df.loc[selected_index]
            status_options = ["Pending", "Resolved", "Unresolved"]
            current_status = row.get("Resolution_Status", "Pending")
            status_index = status_options.index(current_status) if current_status in status_options else 0
            status = st.selectbox("Resolution Status", status_options, index=status_index, key="esc_review_status")
            notes_val = "" if pd.isna(row.get("Admin_Notes", "")) else str(row.get("Admin_Notes", ""))
            reason_val = "" if pd.isna(row.get("Unresolved_Reason", "")) else str(row.get("Unresolved_Reason", ""))
            notes = st.text_area("Admin Notes", value=notes_val, key="esc_review_notes")
            unresolved_reason = st.text_input("Unresolved Reason (if any)", value=reason_val, key="esc_review_reason")
            if st.button("Save Review", key="save_esc_review", use_container_width=True):
                if upsert_escalation_review(selected_index, status, notes.strip(), unresolved_reason.strip()):
                    st.success("Review saved.")
                else:
                    st.error("Unable to save review.")


# Page configuration

st.set_page_config(page_title="AIT Support Center", layout="wide", page_icon="")

# Initialize Session State
if "messages" not in st.session_state:
    st.session_state.messages = []
if "vector_store" not in st.session_state:
    st.session_state.vector_store = load_vector_store()
if "failure_count" not in st.session_state:
    st.session_state.failure_count = 0
if "user_name" not in st.session_state:
    st.session_state.user_name = "Guest"
if "user_dept" not in st.session_state:
    st.session_state.user_dept = "Unknown"
if "user_role" not in st.session_state:
    st.session_state.user_role = "user"
if "session_topics" not in st.session_state:
    st.session_state.session_topics = []
if "replacement_items" not in st.session_state:
    st.session_state.replacement_items = []
if "shift_report" not in st.session_state:
    st.session_state.shift_report = ""
if "replacement_ticket" not in st.session_state:
    st.session_state.replacement_ticket = None
if "replacement_prompt_id" not in st.session_state:
    st.session_state.replacement_prompt_id = ""
if "replacement_pending" not in st.session_state:
    st.session_state.replacement_pending = None
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "escalation_logged" not in st.session_state:
    st.session_state.escalation_logged = []
if "high_priority_logged" not in st.session_state:
    st.session_state.high_priority_logged = []
if "conversation_summary" not in st.session_state:
    st.session_state.conversation_summary = ""
if "summary_counter" not in st.session_state:
    st.session_state.summary_counter = 0
if "show_shift_report" not in st.session_state:
    st.session_state.show_shift_report = False
if "replacement_evidence_cache" not in st.session_state:
    st.session_state.replacement_evidence_cache = {}
if "critical_cache" not in st.session_state:
    st.session_state.critical_cache = {}
if "ticket_cache" not in st.session_state:
    st.session_state.ticket_cache = {}

st.title("AIT Support Center")

# UI styling (Dockyard Console)
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Sora:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
    :root {
        --bg: #0b1016;
        --panel: #121821;
        --panel-2: #18212d;
        --text: #e6edf3;
        --muted: #9aa7b5;
        --accent: #2dd4bf;
        --accent-2: #7dd3fc;
        --warning: #f2a900;
        --danger: #e05252;
        --border: #263142;
        --glow: rgba(45, 212, 191, 0.22);
    }
    html, body, [class*="stApp"] {
        background:
            radial-gradient(1100px 700px at 8% -20%, #1a2330 0%, #0b1016 55%),
            linear-gradient(180deg, rgba(255,255,255,0.04) 1px, transparent 1px),
            linear-gradient(90deg, rgba(255,255,255,0.03) 1px, transparent 1px);
        background-size: auto, 36px 36px, 36px 36px;
        background-attachment: fixed;
        color: var(--text);
        font-family: 'Sora', sans-serif;
    }
    .block-container {
        padding-top: 2.8rem;
        max-width: 1180px;
    }
    h1, h2, h3, h4 {
        color: var(--text);
        letter-spacing: 0.15px;
    }
    .stSidebar [class*="stMarkdown"] p,
    .stSidebar [class*="stMarkdown"] span {
        color: var(--muted);
    }
    [data-testid="stChatMessage"] {
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 0.6rem 1rem;
        background: linear-gradient(180deg, rgba(18, 24, 33, 0.95) 0%, rgba(11, 16, 22, 0.95) 100%);
        box-shadow: 0 10px 28px rgba(0,0,0,0.28);
        margin-bottom: 0.8rem;
        position: relative;
    }
    [data-testid="stChatMessage"]::before {
        content: "";
        position: absolute;
        left: 0;
        top: 0;
        bottom: 0;
        width: 3px;
        background: linear-gradient(180deg, var(--accent) 0%, rgba(45, 212, 191, 0.1) 100%);
        border-radius: 10px 0 0 10px;
    }
    [data-testid="stChatMessage"] p {
        color: var(--text);
    }
    .stButton > button {
        background: rgba(18, 24, 33, 0.9);
        color: var(--text);
        border: 1px solid var(--border);
        border-radius: 6px;
        font-weight: 600;
        transition: transform 0.08s ease, box-shadow 0.2s ease, border-color 0.2s ease;
        box-shadow: 0 6px 18px rgba(0,0,0,0.25);
    }
    .stButton > button:hover {
        transform: translateY(-1px);
        border-color: var(--accent);
        box-shadow: 0 0 0 2px rgba(45, 212, 191, 0.15), 0 10px 24px rgba(0,0,0,0.35);
    }
    .stButton > button:focus {
        outline: 2px solid var(--accent);
        outline-offset: 2px;
    }
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, var(--panel) 0%, #0b1016 100%);
        border-right: 1px solid var(--border);
    }
    .stTextArea textarea, .stTextInput input {
        background: var(--panel-2);
        color: var(--text);
        border: 1px solid var(--border);
        border-radius: 6px;
    }
    .stTextArea textarea:focus, .stTextInput input:focus {
        border-color: var(--accent);
        box-shadow: 0 0 0 2px rgba(45, 212, 191, 0.2);
    }
    .stInfo, .stSuccess, .stWarning, .stError {
        border-radius: 8px;
        border: 1px solid var(--border);
        background: var(--panel-2);
    }
    .loader-wrap {
        position: fixed;
        inset: 0;
        display: flex;
        align-items: center;
        justify-content: center;
        backdrop-filter: blur(2px);
        background: rgba(8, 12, 16, 0.55);
        z-index: 1000;
        padding: 24px;
    }
    .loader-card {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 12px 18px;
        border-radius: 8px;
        border: 1px solid rgba(45, 212, 191, 0.3);
        background: linear-gradient(90deg, rgba(18,24,33,0.9) 0%, rgba(24,33,45,0.9) 100%);
        color: var(--muted);
        font-weight: 500;
        box-shadow: 0 12px 30px rgba(0,0,0,0.35);
    }
    .loader-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: var(--accent-2);
        box-shadow: 0 0 10px rgba(0, 194, 168, 0.5);
        animation: pulse 1.2s infinite ease-in-out;
    }
    .loader-dot:nth-child(2) { animation-delay: 0.2s; }
    .loader-dot:nth-child(3) { animation-delay: 0.4s; }
    @keyframes pulse {
        0%, 100% { transform: scale(0.8); opacity: 0.5; }
        50% { transform: scale(1.2); opacity: 1; }
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Identity gate
if not st.session_state.authenticated:
    st.subheader("Identity Verification")
    st.write("Access is restricted to authorized staff.")
    with st.form("auth_form"):
        name_input = st.text_input("Full Name")
        dept_input = st.text_input("Department")
        submitted = st.form_submit_button("Verify Access")
    if submitted:
        role = authorize_user(name_input, dept_input)
        if role:
            st.session_state.user_name = name_input.strip()
            st.session_state.user_dept = dept_input.strip()
            st.session_state.user_role = role
            st.session_state.authenticated = True
            st.rerun()
        else:
            st.error("Access denied. Your identity was not found in the directory.")
    st.stop()

# Sidebar
with st.sidebar:
    st.header("Settings")
    
    
    st.subheader("User Profile")
    st.info(f"User: {st.session_state.user_name}\n\nDept: {st.session_state.user_dept}")
    if st.button("Sign Out", use_container_width=True):
        st.session_state.authenticated = False
        st.session_state.user_name = "Guest"
        st.session_state.user_dept = "Unknown"
        st.session_state.user_role = "user"
        st.session_state.messages = []
        st.session_state.failure_count = 0
        st.session_state.conversation_summary = ""
        st.session_state.summary_counter = 0
        st.session_state.escalation_logged = []
        st.session_state.high_priority_logged = []
        st.session_state.shift_report = ""
        st.session_state.show_shift_report = False
        st.session_state.replacement_ticket = None
        st.session_state.replacement_prompt_id = ""
        st.session_state.replacement_pending = None
        st.rerun()

    st.divider()

    # Admin Access via Dialog (admin-only)
    if st.session_state.user_role == "admin":
        if st.button("Admin Dashboard", use_container_width=True):
            admin_login_dialog()
    else:
        st.info("Admin tools are hidden for non-admin roles.")
    
    st.divider()

    st.subheader("Ticket Status Lookup")
    ticket_id_input = st.text_input("Ticket ID")
    if st.button("Check Status", use_container_width=True):
        result = find_ticket_status(ticket_id_input.strip())
        if not result:
            st.warning("Ticket not found.")
        else:
            status = (result.get("status") or "").strip()
            admin_notes = (result.get("admin_notes") or "").strip()
            unresolved_reason = (result.get("unresolved_reason") or "").strip()
            unresolved_statuses = {"unresolved", "denied"}
            if status.lower() in unresolved_statuses:
                st.info(admin_notes or unresolved_reason or "No admin notes available.")
            else:
                st.success(f"Status: {status or 'Pending'}")
                if admin_notes:
                    st.info(admin_notes)

    st.divider()
    
    # Knowledge Management removed from main sidebar (moved to Admin Popover)
    if st.session_state.user_role == "admin":
        if st.button("Generate Shift Report", use_container_width=True):
            if st.session_state.messages:
                llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0)
                history_text = "\n".join(
                    f"{m['role'].upper()}: {m['content']}" for m in st.session_state.messages
                )
                topics_text = ", ".join(sorted(set(st.session_state.session_topics))) or "None"
                replacements_text = (
                    f"{len(st.session_state.replacement_items)}x "
                    f"{', '.join(st.session_state.replacement_items)}"
                    if st.session_state.replacement_items
                    else "None"
                )
                report_prompt = (
                    "Summarize this session for a shift handoff. "
                    "Return only two short lines:\n"
                    "- Major Issues: <short phrase>\n"
                    "- Pending Items: <short phrase>\n\n"
                    f"Topics: {topics_text}\n\n"
                    f"Conversation:\n{history_text}"
                )
                summary = llm.invoke(report_prompt).content.strip()
                today = aest_now().strftime("%Y-%m-%d")
                df_hp = load_high_priority_tickets()
                if not df_hp.empty:
                    pending_hp = df_hp[df_hp["Status"] == "Pending"]
                    pending_count = len(pending_hp)
                    recent_hp = df_hp.tail(3)["Issue_Summary"].tolist()
                else:
                    pending_count = 0
                    recent_hp = []
                major_issues, pending_items = parse_shift_summary(summary)
                recent_hp_lines = "\n".join([f"- {item}" for item in recent_hp]) if recent_hp else "- None"
                report_text = (
                    f"SHIFT HANDOFF REPORT - {today}\n\n"
                    "MAJOR ISSUES\n"
                    f"- {major_issues}\n\n"
                    "PENDING ITEMS\n"
                    f"- {pending_items}\n\n"
                    "HARDWARE REPLACEMENTS\n"
                    f"- {replacements_text}\n\n"
                    "HIGH PRIORITY TICKETS\n"
                    f"- Pending: {pending_count}\n"
                    "- Recent:\n"
                    f"{recent_hp_lines}"
                )
                st.session_state.shift_report = report_text
            else:
                st.session_state.shift_report = (
                    "SHIFT HANDOFF REPORT - N/A\n\n"
                    "MAJOR ISSUES\n"
                    "- None\n\n"
                    "PENDING ITEMS\n"
                    "- None\n\n"
                    "HARDWARE REPLACEMENTS\n"
                    "- None\n\n"
                    "HIGH PRIORITY TICKETS\n"
                    "Pending: 0\n"
                    "Recent:\n"
                    "- None"
                )
            st.session_state.show_shift_report = True
            st.rerun()
    
    if st.button("Clear Chat History", use_container_width=True):
        st.session_state.messages = []
        st.session_state.failure_count = 0
        st.session_state.conversation_summary = ""
        st.session_state.summary_counter = 0
        st.session_state.escalation_logged = []
        st.session_state.high_priority_logged = []
        st.session_state.replacement_ticket = None
        st.session_state.replacement_prompt_id = ""
        st.session_state.replacement_pending = None
        st.rerun()
        # ... (? Clear History ?)
        st.session_state.messages = []
        st.session_state.failure_count = 0
        st.session_state.conversation_summary = ""
        st.session_state.summary_counter = 0
        st.session_state.escalation_logged = []
        st.session_state.high_priority_logged = []
        st.session_state.replacement_ticket = None
        st.session_state.replacement_prompt_id = ""
        st.session_state.replacement_pending = None
        st.rerun()
    
    if st.session_state.vector_store:
        st.success(" System Ready")
    else:
        st.warning(" Knowledge Base Missing")

# Display Chat History
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Detailed shift report view
if st.session_state.get("show_shift_report") and st.session_state.shift_report:
    st.divider()
    st.subheader("Shift Handoff Report")
    st.markdown(st.session_state.shift_report)
    report_json = json.dumps(st.session_state.shift_report)
    components.html(
        f"""
        <button id="copy-shift-report" style="width: 100%; padding: 10px; border-radius: 6px; border: 1px solid #ccc;">
            Copy to Clipboard
        </button>
        <script>
            const reportText = {report_json};
            const btn = document.getElementById("copy-shift-report");
            btn.addEventListener("click", () => {{
                navigator.clipboard.writeText(reportText);
                btn.innerText = "Copied!";
                setTimeout(() => (btn.innerText = "Copy to Clipboard"), 1200);
            }});
        </script>
        """,
        height=60,
    )
    if st.button("Close Shift Report", use_container_width=True):
        st.session_state.show_shift_report = False
        st.rerun()

# Replacement confirmation panel (persists across reruns)
if st.session_state.replacement_pending or st.session_state.replacement_ticket:
    st.divider()
    st.subheader("IT Vending Machine Protocol")
    if st.session_state.replacement_ticket:
        ticket = st.session_state.replacement_ticket
        status = ticket.get("status", "Requested")
        if status == "Requested":
            st.info("Replacement request submitted. IT will review the device status before approval.")
            st.info(
                f"**Status:** Requested for Review\n\n"
                f"**Item:** {ticket['device']}\n\n"
                f"**Notes:** {ticket.get('reason', 'N/A')}\n\n"
                f"**Ticket ID:** {ticket.get('ticket_id', 'N/A')}"
            )
        else:
            st.success("Digital Replacement Ticket")
            st.info(
                f"**Status:** Approved for Immediate Replacement\n\n"
                f"**Item:** {ticket['device']}\n\n"
                f"**Location:** IT Vending Locker (Zone B)\n\n"
                f"**OTP Code:** {ticket.get('otp', '')}\n\n"
                "**Instruction:** Enter this code at the locker to collect your device."
            )
        if st.button("Dismiss Ticket Panel", use_container_width=True):
            st.session_state.replacement_ticket = None
            st.session_state.replacement_prompt_id = ""
            st.session_state.replacement_pending = None
            st.rerun()
    else:
        pending = st.session_state.replacement_pending
        prompt_id = pending["prompt_id"]
        st.warning("Hardware replacement requires confirmation to prevent misuse.")
        asset_tag_input = st.text_input(
            "Asset Tag (if available)",
            key=f"replacement_asset_tag_{prompt_id}",
        )
        reason = st.text_input(
            "Confirm the issue or asset tag (required)",
            key=f"replacement_reason_{prompt_id}",
        )
        evidence_files = st.file_uploader(
            "Upload evidence (photo/log required)",
            type=["png", "jpg", "jpeg", "pdf", "txt"],
            accept_multiple_files=True,
            key=f"replacement_evidence_{prompt_id}",
        )
        st.caption(
            f"Limits: {MAX_EVIDENCE_FILES} files, {MAX_EVIDENCE_MB} MB each, "
            f"{MAX_EVIDENCE_TOTAL_MB} MB total."
        )
        confirmed = st.checkbox(
            "I confirm this device is actually malfunctioning and needs replacement.",
            key=f"replacement_confirm_{prompt_id}",
        )
        approve_clicked = st.button(
            "Submit Replacement Request",
            key=f"approve_replacement_{prompt_id}",
            use_container_width=True,
        )
        if st.button("Cancel Replacement Request", use_container_width=True):
            st.session_state.replacement_ticket = None
            st.session_state.replacement_prompt_id = ""
            st.session_state.replacement_pending = None
            st.rerun()
        if approve_clicked:
            if not confirmed or not reason.strip():
                st.error("Please confirm and provide a reason/asset tag before approval.")
            elif not evidence_files:
                st.error("Evidence is required before submitting the request.")
            else:
                ok, msg = validate_evidence_files(evidence_files)
                if not ok:
                    st.error(msg)
                else:
                    device_name = pending["device"]
                    saved_evidence = save_evidence_files(evidence_files, prompt_id)
                    ticket_id = generate_ticket_id("replacement")
                    st.session_state.replacement_items.append(device_name)
                    st.session_state.replacement_ticket = {
                        "device": device_name,
                        "reason": reason.strip(),
                        "status": "Requested",
                        "ticket_id": ticket_id,
                    }
                    st.session_state.replacement_pending = None
                    log_replacement_request(
                        st.session_state.user_name,
                        st.session_state.user_dept,
                        device_name,
                        reason.strip(),
                        asset_tag_input.strip(),
                        "|".join(saved_evidence),
                        "",
                        "Requested",
                        ticket_id,
                    )
                    st.success(f"Replacement request submitted for review. Ticket ID: {ticket_id}")

# User Input
if prompt := st.chat_input("How can I help you today?"):
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        clean_response = "" # Initialize to avoid unbound error
        ticket_id_request = is_ticket_id_request(prompt)
        if ticket_id_request:
            last_ticket = None
            for kind in ("high_priority", "escalation", "replacement"):
                recent = st.session_state.ticket_cache.get(f"{kind}:_last")
                if recent:
                    last_ticket = recent["ticket_id"]
                    break
            if last_ticket:
                clean_response = (
                    f"Your most recent ticket ID is {last_ticket}. "
                    "Use the Ticket Status lookup to check its status."
                )
            else:
                clean_response = (
                    "I don't have a recent ticket ID on record. "
                    "Please use the Ticket Status lookup or contact IT support."
                )
            st.markdown(clean_response)
            log_interaction(
                prompt,
                "Other",
                True,
                st.session_state.user_name,
                st.session_state.user_dept,
            )
            st.session_state.session_topics.append("Other")
        elif st.session_state.vector_store is None:
            clean_response = " The IT Knowledge Base is missing. Please contact an admin."
            st.markdown(clean_response)
        else:
            try:
                llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0)
                
                # 1. Classify Topic
                category = classify_topic(prompt, llm)

                reviews_df = load_escalation_reviews()
                admin_notes = "None"
                if not reviews_df.empty:
                    reviewed = reviews_df[reviews_df["Resolution_Status"] != "Pending"]
                    if not reviewed.empty:
                        recent = reviewed.tail(5)
                        lines = []
                        for _, row in recent.iterrows():
                            question = "" if pd.isna(row.get("User_Question", "")) else str(row.get("User_Question", ""))
                            status = "" if pd.isna(row.get("Resolution_Status", "")) else str(row.get("Resolution_Status", ""))
                            notes = "" if pd.isna(row.get("Admin_Notes", "")) else str(row.get("Admin_Notes", ""))
                            reason = "" if pd.isna(row.get("Unresolved_Reason", "")) else str(row.get("Unresolved_Reason", ""))
                            line = f"- Q: {question} | Status: {status} | Notes: {notes}"
                            if reason:
                                line += f" | Unresolved Reason: {reason}"
                            lines.append(line)
                        admin_notes = "\n".join(lines) if lines else "None"

                # Update conversation summary every 5 user turns to save tokens
                if st.session_state.summary_counter % 5 == 0:
                    new_summary = update_conversation_summary(st.session_state.messages, llm)
                    if new_summary:
                        st.session_state.conversation_summary = new_summary
                st.session_state.summary_counter += 1

                recent_context = build_recent_context(st.session_state.messages, limit=6)

                system_prompt = (
                    "You are a professional IT Support Assistant. Use the provided context to answer questions.\n\n"
                    "CONVERSATION SUMMARY:\n"
                    f"{st.session_state.conversation_summary or 'None'}\n\n"
                    "RECENT CHAT:\n"
                    f"{recent_context or 'None'}\n\n"
                    "ADMIN REVIEW NOTES:\n"
                    f"{admin_notes}\n\n"
                    "ESCALATION RULES:\n"
                    "1. If the user mentions hardware damage (smoke, broken screen, fire, complex wiring), "
                    "inform them a specialist is needed and use [ESC_VIDEO].\n"
                    "2. If the user explicitly asks to speak to a human, specialist, or live support, "
                    "acknowledge the request and use [ESC_VIDEO].\n"
                    "3. For password resets, point to the 'Self-Service Portal' and DO NOT use [ESC_VIDEO].\n"
                    "4. If the issue is a hardware failure that cannot be fixed remotely (dead battery, broken screen), "
                    "do not provide manual fixes and use [ESC_REPLACE].\n"
                    "5. If no answer is found, say you can't find it in the manual and use [ESC_FAIL].\n\n"
                    "6. Always end your response with exactly one tag: [ESC_VIDEO], [ESC_REPLACE], [ESC_FAIL], or [ESC_NONE].\n\n"
                    "Context: {context}"
                )
                
                prompt_template = ChatPromptTemplate.from_messages([
                    ("system", system_prompt),
                    ("human", "{input}"),
                ])
                
                combine_docs_chain = create_stuff_documents_chain(llm, prompt_template)
                retriever = st.session_state.vector_store.as_retriever(search_kwargs={"k": 5})
                rag_chain = create_retrieval_chain(retriever, combine_docs_chain)
                
                loader = st.empty()
                loader.markdown(
                    """
                    <div class="loader-wrap">
                        <div class="loader-card">
                            <div class="loader-dot"></div>
                            <div class="loader-dot"></div>
                            <div class="loader-dot"></div>
                            <span>Consulting manuals and depot logs...</span>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                result = rag_chain.invoke({"input": prompt})
                response = ensure_escalation_tag(result["answer"], llm)
                loader.empty()
                
                resolved = True
                if "[ESC_FAIL]" in response:
                    st.session_state.failure_count += 1
                    resolved = False
                else:
                    st.session_state.failure_count = 0
                
                # 2. Log to CSV (Included User Metadata)
                log_interaction(
                    prompt, 
                    category, 
                    resolved, 
                    st.session_state.user_name, 
                    st.session_state.user_dept
                )
                
                # Track topics for the session report
                st.session_state.session_topics.append(category)

                # Clean the response for display
                clean_response = (
                    response.replace("[ESC_VIDEO]", "")
                    .replace("[ESC_FAIL]", "")
                    .replace("[ESC_REPLACE]", "")
                    .replace("[ESC_NONE]", "")
                    .strip()
                )

                cache_key = f"{len(st.session_state.messages)}:{prompt}"
                if cache_key in st.session_state.critical_cache:
                    critical_incident = st.session_state.critical_cache[cache_key]
                else:
                    critical_incident = is_critical_incident_llm(
                        prompt,
                        st.session_state.conversation_summary,
                        llm,
                    )
                    st.session_state.critical_cache[cache_key] = critical_incident
                replacement_needed = is_replacement_case(prompt, response)
                if replacement_needed and not critical_incident:
                    device_name = detect_device(prompt)
                    prompt_id = f"{len(st.session_state.messages)}:{prompt}"
                    if st.session_state.replacement_prompt_id != prompt_id:
                        st.session_state.replacement_prompt_id = prompt_id
                        st.session_state.replacement_ticket = None
                        st.session_state.replacement_pending = {
                            "prompt_id": prompt_id,
                            "device": device_name,
                            "prompt": prompt,
                        }
                    clean_response = "Replacement flow started. Please confirm in the replacement panel."
                    st.markdown(clean_response)
                    st.rerun()
                else:
                    st.markdown(clean_response)

                prompt_id = f"{len(st.session_state.messages)}:{prompt}"
                # Logic for which buttons to show
                is_password_reset = "self-service portal" in clean_response.lower() and "[ESC_VIDEO]" not in response
                show_video_button = (
                    "[ESC_VIDEO]" in response
                    or st.session_state.failure_count >= 3
                    or critical_incident
                    or is_escalation_response(response)
                )
                
                if replacement_needed and not critical_incident:
                    pass
                elif show_video_button:
                    # Summarize issue for logging and email draft
                    issue_context = summarize_issue_for_email(
                        st.session_state.messages,
                        llm,
                        prompt,
                    )
                    if critical_incident and prompt_id not in st.session_state.high_priority_logged:
                        ticket_id, created = get_or_create_ticket("high_priority", issue_context, prompt)
                        if created:
                            log_high_priority_ticket(
                                st.session_state.user_name,
                                st.session_state.user_dept,
                                issue_context,
                                ticket_id,
                            )
                        st.session_state.high_priority_logged.append(prompt_id)
                        st.warning(f"High-priority ticket: {ticket_id}")
                    if not critical_incident and prompt_id not in st.session_state.escalation_logged:
                        esc_type = "Video/E-mail"
                        ticket_id, created = get_or_create_ticket("escalation", issue_context, prompt)
                        if created:
                            log_escalation_event(
                                st.session_state.user_name,
                                st.session_state.user_dept,
                                issue_context,
                                esc_type,
                                ticket_id,
                            )
                        st.session_state.escalation_logged.append(prompt_id)
                        st.info(f"Escalation ticket: {ticket_id}")
                    st.divider()
                    col_vid, col_mail = st.columns(2)

                    with col_vid:
                        if is_aest_business_hours():
                            st.error("Specialist Needed")
                            teams_url = "https://teams.microsoft.com/l/call/0/0?users=support@freshflow.com"
                            st.link_button("Video Call IT Support", teams_url, use_container_width=True)
                        else:
                            st.warning("After-Hours")
                            st.write("Live support: 08:00 - 18:00 (AEST).")
                            st.link_button("Open High Priority Ticket Demo", DEMO_HIGH_PRIORITY_URL, use_container_width=True)
                            if st.button("Log High Priority Ticket", use_container_width=True):
                                if prompt_id not in st.session_state.high_priority_logged:
                                    ticket_id, created = get_or_create_ticket("high_priority", issue_context, prompt)
                                    if created:
                                        log_high_priority_ticket(
                                            st.session_state.user_name,
                                            st.session_state.user_dept,
                                            issue_context,
                                            ticket_id,
                                        )
                                    st.session_state.high_priority_logged.append(prompt_id)
                                st.success(f"High-priority ticket: {ticket_id}")

                    with col_mail:
                        if critical_incident:
                            st.info("High-priority incident logged. Email draft disabled for critical incidents.")
                            st.link_button("Open High Priority Ticket Demo", DEMO_HIGH_PRIORITY_URL, use_container_width=True)
                        else:
                            st.info("Support Ticket Draft")
                            timestamp = aest_now().strftime("%Y%m%d-%H%M")

                            # Reuse summarized context for the ticket draft

                            email_subject = f"[Support Request] {st.session_state.user_dept} - {st.session_state.user_name}"
                            email_body = (
                                f"Hi IT Team,\n\n"
                                f"I am experiencing an issue. Context from chat:\n"
                                f"------------------------------------------\n"
                                f"{issue_context}\n"
                                f"------------------------------------------\n\n"
                                f"Reference Code: {timestamp}\n"
                                f"User: {st.session_state.user_name} ({st.session_state.user_dept})"
                            )

                            # Encode for mailto link
                            subject_encoded = urllib.parse.quote(email_subject)
                            body_encoded = urllib.parse.quote(email_body)
                            mailto_link = f"mailto:support@freshflow.com?subject={subject_encoded}&body={body_encoded}"

                            # Provide a mailto button and a copyable block
                            st.link_button("Open Email Client", mailto_link, use_container_width=True)

                            st.info("If the button above doesn't open your email app, please use the box below to copy the text manually.")

                            with st.expander("View & Copy Draft Text", expanded=True):
                                st.code(f"Subject: {email_subject}\n\n{email_body}", language="text")

                elif is_password_reset:
                    st.link_button(" Go to Password Portal", "https://sso-portal.yourcompany.com")
            except Exception as e:
                clean_response = f"Error: {str(e)}"
                st.error(clean_response)
        
        if clean_response:
            st.session_state.messages.append({"role": "assistant", "content": clean_response})
