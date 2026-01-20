# ait-support-de for ICB Group PTY LTD

[AIT Support] Final Project Report 
Project Title: AIT Support (AI-Driven IT Infrastructure & Operations System)
Target Environment: Fast-Moving Consumer Goods (FMCG) Warehouse & Corporate Office
________________________________________
#1. Executive Summary
"More than a chatbot: An operational system designed to protect warehouse throughput and reduce downtime."
This project addresses the critical time-sensitivity of IT support in 24/7 FMCG logistics environments. Traditional linear support models (Ticket → Wait → Triage) are too slow for high-velocity operations where a single scanner failure can impact order SLAs.
AIT Support bridges this gap by combining AI-driven triage with strict operational controls. It automates repetitive Level 1 tasks while enforcing rigorous workflows for hardware replacements and high-priority incidents, ensuring that the IT team focuses on infrastructure stability rather than administrative noise.
________________________________________
#2. Problem Statement
In a continuously operating warehouse, IT friction translates directly to business loss.
•	Cost of Downtime: When critical hardware (scanners, label printers) fails, operations stop until IT arrives.
o	Context: According to ITIC (2024), 90% of enterprises report that a single hour of downtime costs over $300,000, highlighting the financial criticality of rapid resolution [1].
•	Inefficient Resource Allocation: Skilled IT staff are often bogged down by repetitive, low-value requests.
o	Context: Gartner research indicates that up to 40% of all help desk calls are related to password resets and account lockouts [2]. Furthermore, Forrester estimates the labor cost for a single password reset incident at approximately $70 [3].
•	Shift Handover Risks: Critical information is often lost between shifts, leading to recurring issues.
o	Context: Studies show that 80% of serious operational errors involve miscommunication during shift handovers [4].
•	Information Retrieval Waste: Workers spend excessive time searching for SOPs or manuals.
o	Context: A recent Atlassian report reveals that Australian knowledge workers spend nearly 23.5% (approx. 10 hours) of their work week just searching for information [5].
________________________________________
#3. Technical Architecture
Built on a Modern Data Stack to ensure reliability, auditability, and scalability.
•	Frontend: Streamlit with a custom 'Dockyard Console' theme, optimized for high visibility and ease of use in warehouse environments (gloved operation friendly).
•	Backend: Supabase (PostgreSQL) for relational management of logs, tickets, replacement history, and user roles.
•	AI Engine: Google Gemini (via LangChain) coupled with FAISS for Vector Search. This RAG (Retrieval-Augmented Generation) architecture ensures responses are grounded strictly in internal SOPs, eliminating hallucinations.
•	Security: Role-Based Access Control (RBAC) separates 'User' and 'Admin' privileges to prevent unauthorized actions.
________________________________________
#4. Core Features & Workflows
1) Identity Gate & Security
•	Verifies user identity against an authorized personnel list (Name/Department).
•	Strictly isolates Admin functionalities (approvals, logs) from general users.
2) AI-Driven Support (RAG)
•	Instantly answers troubleshooting queries using indexed internal manuals.
•	Smart Routing: If the AI cannot resolve the issue, it intelligently guides the user to the appropriate escalation path (Specialist or High-Priority).
3) Hardware Replacement Workflow (IT Vending Protocol)
•	Logic: Users must submit evidence (photos/description) for broken devices.
•	Control: The system prevents unauthorized swaps. A replacement OTP (One-Time Password) is generated only after Admin review and approval of the evidence.
4) High-Priority Incident Handling
•	Logic: Bypasses the standard queue for critical events (e.g., Server Outage, Safety Hazards).
•	Action: Immediately logs a P1 ticket and provides the user with emergency protocol guidance.
5) Automated Shift Handoff Report
•	Feature: One-click generation of a shift summary, detailing:
o	Major incidents occurred.
o	Hardware replacements processed.
o	Pending issues requiring follow-up.
•	Impact: Drastically reduces context loss between morning/afternoon/night shifts.
6) Admin Dashboard & Analytics
•	Provides a centralized view for approving replacements, reviewing high-priority tickets, and analyzing recurring issue trends.
•	Captures 'Admin Notes' for audit trails and continuous knowledge base improvement.
________________________________________
#5. Role Alignment
This project demonstrates the core competencies required for an IT Support Specialist:
•	Infrastructure Mindset: Moves beyond "fixing things" to "managing systems" through structured escalation and severity classification.
•	Warehouse Tech Proficiency: Specifically designed for logistics hardware (Zebra scanners, RF terminals) rather than just generic office IT.
•	Operational Discipline: Implements standard operating procedures (SOPs) for handovers and asset management.
•	Cost Awareness: Focuses on reducing call volume (Call Deflection) and minimizing unnecessary hardware expenditures.
________________________________________
#6. Qualitative Impact & Projected ROI
Instead of vanity metrics, this system targets tangible operational improvements:
•	Call Deflection: Projected to resolve ~54% of routine Level 1 inquiries (e.g., Wi-Fi, Password) without human intervention [6].
•	Risk Mitigation: Digital shift reports aim to reduce handover-related operational errors by up to 75% [4].
•	Productivity Gain: By streamlining information retrieval, the system reclaims the 10 hours/week typically lost to searching for answers [5], allowing staff to focus on core logistics tasks.
•	Asset Control: Enforced approval workflows reduce inventory shrinkage and unnecessary device rotation.
________________________________________
#7. Future Roadmap
•	Integrations: Connect with ServiceNow or Zendesk APIs for seamless ticket synchronization.
•	SSO Implementation: Integrate Azure AD or Okta for enterprise-grade authentication.
•	Predictive Maintenance: Utilize log data to predict hardware failures before they disrupt operations.
•	Inventory Link: Real-time connection to the asset management database for instant stock validation.
________________________________________
📎 References
•	[1] ITIC (2024): "Hourly Cost of Downtime Survey" (90% of enterprises report >$300k cost per hour of downtime).
•	[2] Gartner: "Market Guide for Service Desk Automation" (Estimates ~40% of help desk calls relate to password resets).
•	[3] Forrester Research: "Best Practices: Selecting, Deploying, And Managing Enterprise Password Managers" (Calculates ~$70 labor cost per password reset incident).
•	[4] The Joint Commission: "Shift Handover Statistics" (80% of serious errors involve miscommunication during handovers).
•	[5] Atlassian (2025): "State of Teams Report Australia" (Australian knowledge workers spend ~23.5% of work week searching for information).
•	[6] Industry Data: AI-driven self-service tools are estimated to fully resolve 54% of standard customer/employee inquiries.

