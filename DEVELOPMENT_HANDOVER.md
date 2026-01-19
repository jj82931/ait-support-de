# Project Handover: AIT Support Chatbot

## 🎯 Context
This is an IT Support RAG (Retrieval-Augmented Generation) system designed to provide automated support and escalate to human agents via MS Teams when necessary.

## 🛠 Tech Stack
- **Frontend:** Streamlit
- **LLM:** Gemini 2.5 Flash (as requested by user)
- **Embeddings:** `models/embedding-001`
- **Vector DB:** FAISS (Local persistence in `vectorstore/`)
- **Libraries:** LangChain, PyPDFLoader, pytz (for AEST time checks)

## ✅ Key Implementation Details (Session History)

### 1. Persistent Knowledge Base
- **Logic:** Instead of per-session uploads, we implemented a persistent storage.
- **Admin Mode:** Accessible via sidebar. Admins upload PDF/TXT, which are indexed and saved to `vectorstore/faiss_index`.
- **Auto-load:** The app checks for an existing index on startup and loads it automatically.

### 2. Smart Escalation (Human-in-the-loop)
- **Hardware Detection:** If the user mentions "smoke", "fire", "broken screen", or "broken hardware", the AI triggers a red **"Connect to Specialist (Video)"** button immediately.
- **3-Fail Policy:** If the AI fails to find an answer (phrases like "I don't know" or "not in manual") for **3 consecutive times**, the video support button appears.
- **Business Hours (AEST):** Live support is only offered Mon-Fri, 08:00 - 18:00 AEST. Outside these hours, a **"Log High-Priority Ticket"** button is shown instead.

### 3. Routing & Security
- **Password Resets:** Specifically routed to a "Self-Service Portal" link, bypassing live support.
- **Admin Access:** Currently a simple checkbox in the sidebar for development, but structured for future authentication.

## 📂 Current File Structure
- `app.py`: Full source code with RAG chain and escalation logic.
- `.env`: Contains `GOOGLE_API_KEY`.
- `vectorstore/`: Stores the FAISS index files.
- `requirements.txt`: Python dependencies.

## 💡 How to Resume
1. Read `app.py` to understand the specific prompt engineering and escalation tags (`[ESC_VIDEO]`, `[ESC_FAIL]`).
2. Verify the Google API Key in `.env`.
3. Start the app: `streamlit run app.py`.

---
*If starting a new session, read this file first to restore the full project context.*
