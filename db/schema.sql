-- Supabase/Postgres schema
create table if not exists authorized_users (
    id uuid primary key default gen_random_uuid(),
    user_name text not null,
    user_dept text not null,
    role text not null default 'user',
    created_at timestamp with time zone default now()
);

create table if not exists chat_logs (
    id uuid primary key default gen_random_uuid(),
    timestamp text not null,
    user_name text not null,
    user_dept text not null,
    user_question text not null,
    category text not null,
    resolved_by_ai boolean not null default false
);

create table if not exists escalation_reviews (
    id uuid primary key default gen_random_uuid(),
    timestamp text not null,
    user_name text not null,
    user_dept text not null,
    user_question text not null,
    escalation_type text not null,
    resolution_status text not null default 'Pending',
    admin_notes text,
    unresolved_reason text,
    ticket_id text
);

create table if not exists high_priority_tickets (
    id uuid primary key default gen_random_uuid(),
    timestamp text not null,
    user_name text not null,
    user_dept text not null,
    issue_summary text not null,
    status text not null default 'Pending',
    admin_notes text,
    ticket_id text
);

create table if not exists replacement_requests (
    id uuid primary key default gen_random_uuid(),
    timestamp text not null,
    user_name text not null,
    user_dept text not null,
    device text not null,
    reason text not null,
    asset_tag text,
    checklist jsonb,
    evidence_files text,
    remote_diagnostics text,
    status text not null default 'Requested',
    review_status text not null default 'Pending',
    admin_notes text,
    otp text,
    ticket_id text
);

create index if not exists idx_replacement_status on replacement_requests (status);
create index if not exists idx_escalation_status on escalation_reviews (resolution_status);
create index if not exists idx_high_priority_status on high_priority_tickets (status);
