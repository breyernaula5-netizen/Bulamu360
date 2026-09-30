create table if not exists public.bulamu_app_state (
  key text primary key,
  state jsonb not null default '{"orders":[]}'::jsonb,
  updated_at timestamptz not null default now()
);

alter table public.bulamu_app_state enable row level security;

drop policy if exists "service role manages bulamu app state" on public.bulamu_app_state;
create policy "service role manages bulamu app state"
on public.bulamu_app_state
for all
using (auth.role() = 'service_role')
with check (auth.role() = 'service_role');
