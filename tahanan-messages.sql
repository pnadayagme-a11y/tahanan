-- =====================================================================
-- TAHANAN: owner replies (chat threads between renters and owners)
-- Paste everything in Supabase > SQL Editor and click Run. Safe to run twice.
-- =====================================================================

-- 1. Replies table (each reply belongs to one renter inquiry)
create table if not exists public.inquiry_replies(
  id uuid primary key default gen_random_uuid(),
  inquiry_id uuid not null references public.inquiries(id) on delete cascade,
  sender_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  body text not null check (char_length(body) between 1 and 1000),
  read_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists inquiry_replies_inquiry_idx on public.inquiry_replies(inquiry_id, created_at);

-- 2. Remembers when the owner first opened a renter's message ("new" badge)
alter table public.inquiries add column if not exists owner_seen_at timestamptz;

-- 3. Who is this user in a conversation? renter / owner / admin / nobody
create or replace function public.inquiry_role(p_inquiry uuid) returns text
language sql stable security definer set search_path = public as $$
  select case
    when i.renter_id = auth.uid() then 'renter'
    when l.owner_id = auth.uid() then 'owner'
    when exists (select 1 from profiles where id = auth.uid() and role = 'admin') then 'admin'
    else null end
  from inquiries i join listings l on l.id = i.listing_id
  where i.id = p_inquiry;
$$;

-- 4. Security: only the renter, the owner, and admins can read a conversation.
--    Only the renter and the owner can send replies.
alter table public.inquiry_replies enable row level security;
drop policy if exists "replies_select" on public.inquiry_replies;
create policy "replies_select" on public.inquiry_replies for select
  using (public.inquiry_role(inquiry_id) is not null);
drop policy if exists "replies_insert" on public.inquiry_replies;
create policy "replies_insert" on public.inquiry_replies for insert
  with check (sender_id = auth.uid() and public.inquiry_role(inquiry_id) in ('renter','owner'));
grant select, insert on public.inquiry_replies to authenticated;

-- 5. Mark a conversation as read
create or replace function public.mark_thread_read(p_inquiry uuid) returns void
language plpgsql security definer set search_path = public as $$
declare r text := public.inquiry_role(p_inquiry);
begin
  if coalesce(r, '') not in ('renter','owner') then return; end if;
  update inquiry_replies set read_at = now()
   where inquiry_id = p_inquiry and sender_id <> auth.uid() and read_at is null;
  if r = 'owner' then
    update inquiries set owner_seen_at = coalesce(owner_seen_at, now()) where id = p_inquiry;
  end if;
end $$;

-- 6. Summary of my conversations (reply count, unread count, last activity)
create or replace function public.my_threads()
returns table(inquiry_id uuid, replies int, unread int, last_at timestamptz, last_from_me boolean)
language sql stable security definer set search_path = public as $$
  select i.id,
    count(r.id)::int,
    (count(r.id) filter (where r.sender_id <> auth.uid() and r.read_at is null)
      + case when l.owner_id = auth.uid() and i.owner_seen_at is null then 1 else 0 end)::int,
    greatest(i.created_at, max(r.created_at)),
    coalesce((array_agg(r.sender_id order by r.created_at desc))[1] = auth.uid(), i.renter_id = auth.uid())
  from inquiries i
  join listings l on l.id = i.listing_id
  left join inquiry_replies r on r.inquiry_id = i.id
  where i.renter_id = auth.uid() or l.owner_id = auth.uid()
  group by i.id, l.owner_id;
$$;

grant execute on function public.inquiry_role(uuid) to authenticated;
grant execute on function public.mark_thread_read(uuid) to authenticated;
grant execute on function public.my_threads() to authenticated;

-- 7. Refresh Supabase so the website sees the new table right away
notify pgrst, 'reload schema';
