-- NOTE: only admins use password_hash. Clients log in with name + roll no + phone and store the placeholder '!' here.
-- TakeHelp? database schema (SQLite). Max active orders (15) is also enforced by the two triggers at the bottom.
create table if not exists users(id integer primary key, name text not null, roll_no text unique, username text unique, phone text,
  password_hash text not null, role text not null check(role in ('client','admin')), created_at text default (datetime('now')));
create table if not exists pricing(id integer primary key check(id=1), page real not null, drawing real not null, tbl real not null,
  graph real not null, simple_diagram real not null, detailed_diagram real not null);
create table if not exists orders(id integer primary key, code text unique, client_id integer not null references users(id),
  type text not null, subject text not null, due_date text not null,
  pages integer not null check(pages>0), drawings integer not null default 0, tables_n integer not null default 0, graphs integer not null default 0,
  simple_diagrams integer not null default 0, detailed_diagrams integer not null default 0, comments text default '',
  estimated real not null check(estimated>=100), final_price real check(final_price is null or final_price>=100),
  status text not null default 'New' check(status in ('New','Accepted','Waiting List','In Progress','Completed','Cancelled')),
  priority text not null default 'Low', priority_manual integer not null default 0, admin_notes text default '',
  created_at text default (datetime('now')), updated_at text default (datetime('now')));
create table if not exists files(id integer primary key, order_id integer not null references orders(id) on delete cascade,
  role text, original_name text not null, stored_name text not null, mime text not null, size integer, created_at text default (datetime('now')));
create table if not exists notifications(id integer primary key, user_id integer not null references users(id) on delete cascade,
  message text not null, is_read integer default 0, created_at text default (datetime('now')));
create table if not exists order_history(id integer primary key, order_id integer not null references orders(id) on delete cascade,
  status text not null, created_at text default (datetime('now')));
create trigger if not exists cap_ins before insert on orders when new.status in ('New','Accepted','In Progress')
  and (select count(*) from orders where status in ('New','Accepted','In Progress'))>=15 begin select raise(abort,'CAPACITY'); end;
create trigger if not exists cap_upd before update of status on orders when new.status in ('New','Accepted','In Progress') and old.status not in ('New','Accepted','In Progress')
  and (select count(*) from orders where status in ('New','Accepted','In Progress'))>=15 begin select raise(abort,'CAPACITY'); end;
