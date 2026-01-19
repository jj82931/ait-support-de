# Project Progress: AIT Support Chatbot Upgrade

## 🎯 Current Status
The AIT Support RAG system has been upgraded with advanced automation, logging, and administrative features. The system is designed to handle IT support queries using Gemini 2.5 Flash and provides smart escalation paths when AI resolution is not possible.

## 🛠 Features Implemented

### 1. SSO & Persona Simulation
- **Persona Switcher:** Added a sidebar selector for "Warehouse Operator", "Office Staff", and "Guest".
- **Dynamic Metadata:** Automatically populates `User_Name` and `User_Dept` based on the selected persona, ensuring all logs and support tickets carry the correct context.

### 2. Smart Escalation & Human Handoff
- **Intelligent Routing:** System triggers escalation for hardware-related keywords or after 3 consecutive answer failures.
- **Support Channels:**
    - **Video Call:** Direct link to MS Teams for live specialist support.
    - **Smart Email Draft:** Generates a pre-formatted email ticket.
- **Context-Aware Emailing:** The email draft logic scans chat history to include the *actual* technical issue (e.g., specific error codes) even if the last message was just "connect me to a human".
- **Mailto Integration:** Includes a "Launch Email Client" button with a copyable text fallback for high reliability.

### 3. Admin Insight Dashboard (V2)
- **Centralized UI:** Replaced popovers with a centered, large-scale `@st.dialog` for a better dashboard experience without UI clipping.
- **Three-Tiered Analytics:**
    - **Analytics Tab:** Real-time bar charts of recurring issues and "Cost Efficiency ROI" metrics ($15 saved per AI resolution).
    - **Knowledge Management Tab:** Exclusive admin area for uploading PDF/TXT manuals and viewing current active files.
    - **Knowledge Gap Analysis:** Uses Gemini to analyze unresolved logs and generate actionable "Manual Update Suggestions" to close support gaps.

### 4. Robust Logging System
- **Enhanced Schema:** `chat_logs.csv` now tracks `Timestamp`, `User_Name`, `User_Dept`, `User_Question`, `Category`, and `Resolution_Status`.
- **Auto-Migration:** Logic included to detect old log formats and automatically migrate them to the new schema to prevent `ParserError`.

## 📂 File Structure Changes
- `app.py`: Main logic containing the Streamlit UI, RAG chain, and Admin functionalities.
- `chat_logs.csv`: Persistent database for analytics.
- `vectorstore/source_files.txt`: Tracks currently indexed manuals.
- `requirements.txt`: Added `pandas` and `pytz` for data handling.

## 💡 Notes for Next AI Agent
- **LLM:** Currently using `gemini-2.5-flash`.
- **Vector DB:** FAISS is persisted in `vectorstore/`.
- **Admin Password:** Default is `admin123`.
- **AEST Timezone:** Escalation logic depends on `Australia/Sydney` business hours (08:00 - 18:00).
