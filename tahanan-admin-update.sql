-- =====================================================================
-- TAHANAN · Admin panel update
--   * Listing approval (pending / approved / declined)
--   * Tahanan Pro subscription + GCash payment requests
--   * Ad priority (paid ranking, like PPC)
--   * Editable marketing content (promo banner, homepage, Pro price)
--   * Listing reports (scam / fake photos)
--   * Admin data: users, owners, renters, traffic
--   * Security lock (nobody can make themselves admin or Pro)
-- Run this AFTER the main setup, the promo update and the analytics update.
-- Safe to run again.
-- Supabase > SQL Editor > New query > paste ALL > Run
-- =====================================================================


-- ---------------------------------------------------------------------
-- 1. SITE SETTINGS (marketing content the admin can edit)
-- ---------------------------------------------------------------------
create table if not exists public.site_settings (
  key         text primary key,
  value       jsonb not null default '{}'::jsonb,
  updated_at  timestamptz not null default now()
);

insert into public.site_settings (key, value) values ('marketing', '{
  "promo_enabled": true,
  "promo_title": "Grand Launch Promo!",
  "promo_text": "Post your room FREE + get a ⭐ Featured spot for 30 days.",
  "promo_button": "Claim my slot →",
  "promo_slots": 50,
  "promo_days": 30,
  "hero_line1": "Find a place",
  "hero_line2": "to call",
  "hero_highlight": "home.",
  "hero_text": "Hanap ka ng tahanan malapit sa school mo? Discover affordable rooms, bedspaces, and apartments around Iligan City.",
  "pro_price": 199,
  "pro_days": 30,
  "pro_benefits": "⭐ Featured on ALL your listings\n🔝 Shown above free listings in search\n📊 Full performance report\n✓ Priority verification",
  "gcash_number": "",
  "gcash_name": ""
}'::jsonb) on conflict (key) do nothing;

alter table public.site_settings enable row level security;
drop policy if exists "Anyone reads settings" on public.site_settings;
create policy "Anyone reads settings" on public.site_settings for select to anon, authenticated using (true);
drop policy if exists "Admins edit settings" on public.site_settings;
create policy "Admins edit settings" on public.site_settings for all to authenticated
  using (public.my_role() = 'admin') with check (public.my_role() = 'admin');
grant select on public.site_settings to anon, authenticated;
grant insert, update, delete on public.site_settings to authenticated;

-- Read one marketing setting (used by the functions below)
create or replace function public.setting(k text) returns text
language sql stable security definer set search_path = public as $$
  select value ->> k from public.site_settings where key = 'marketing'
$$;

-- Promo slots and days now come from the admin Marketing tab
create or replace function public.promo_max_slots() returns int
language sql stable security definer set search_path = public as $$
  select coalesce(nullif(public.setting('promo_slots'), '')::int, 50)
$$;
create or replace function public.promo_days() returns int
language sql stable security definer set search_path = public as $$
  select coalesce(nullif(public.setting('promo_days'), '')::int, 30)
$$;


-- ---------------------------------------------------------------------
-- 2. PROFILES: Pro plan + security lock
-- ---------------------------------------------------------------------
alter table public.profiles add column if not exists plan text not null default 'free';
alter table public.profiles add column if not exists plan_until timestamptz;

-- Users can't make themselves admin or Pro. Only renter -> owner is allowed.
-- Changes from the Supabase dashboard and from admins are allowed.
create or replace function public.profiles_guard()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'INSERT' then
    if new.role is null or new.role not in ('renter','owner') then new.role := 'renter'; end if;
    new.plan := 'free';
    new.plan_until := null;
  elsif auth.uid() is not null and coalesce(public.my_role(),'') <> 'admin' then
    if new.role is distinct from old.role and not (old.role = 'renter' and new.role = 'owner') then
      new.role := old.role;
    end if;
    new.plan := old.plan;
    new.plan_until := old.plan_until;
  end if;
  return new;
end; $$;

drop trigger if exists profiles_guard on public.profiles;
create trigger profiles_guard before insert or update on public.profiles
  for each row execute function public.profiles_guard();


-- ---------------------------------------------------------------------
-- 3. LISTINGS: approval + ad priority
-- ---------------------------------------------------------------------
-- Existing listings stay live (approved). New ones start as pending.
alter table public.listings add column if not exists approval text not null default 'approved'
  check (approval in ('pending','approved','declined'));
alter table public.listings alter column approval set default 'pending';
alter table public.listings add column if not exists decline_reason text;
alter table public.listings add column if not exists reviewed_at timestamptz;
alter table public.listings add column if not exists ad_priority int not null default 0;
create index if not exists listings_approval_idx on public.listings(approval);

-- Listing guard:
--   * owners can't set verified / featured / ad priority / approval themselves
--   * new owner listings start as "pending"
--   * editing a declined listing sends it back for review
--   * when a listing gets APPROVED, the owner's Founding Owner promo
--     and Pro plan make it Featured
create or replace function public.listings_guard()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  is_admin  boolean := coalesce(public.my_role(),'') = 'admin';
  claim_end timestamptz;
  pro_end   timestamptz;
  best_end  timestamptz;
begin
  if not is_admin then
    if tg_op = 'INSERT' then
      new.owner_id       := auth.uid();
      new.verified       := false;
      new.featured_until := null;
      new.ad_priority    := 0;
      new.approval       := 'pending';
      new.decline_reason := null;
      new.reviewed_at    := null;
    else
      new.owner_id       := old.owner_id;
      new.verified       := old.verified;
      new.featured_until := old.featured_until;
      new.ad_priority    := old.ad_priority;
      new.reviewed_at    := old.reviewed_at;
      new.decline_reason := old.decline_reason;
      new.approval       := case when old.approval = 'declined' then 'pending' else old.approval end;
    end if;
  elsif tg_op = 'INSERT' then
    new.owner_id := coalesce(new.owner_id, auth.uid());
    if new.owner_id = auth.uid() then new.approval := 'approved'; end if;  -- admin's own posts go live
  end if;

  if new.approval = 'approved' and (tg_op = 'INSERT' or old.approval is distinct from 'approved') then
    if (select role from public.profiles where id = new.owner_id) = 'owner' then
      perform pg_advisory_xact_lock(424242);
      if coalesce(public.setting('promo_enabled'), 'true') = 'true'
         and not exists (select 1 from public.promo_claims where owner_id = new.owner_id)
         and (select count(*) from public.promo_claims) < public.promo_max_slots() then
        insert into public.promo_claims (owner_id) values (new.owner_id);
      end if;
      select claimed_at + make_interval(days => public.promo_days())
        into claim_end from public.promo_claims where owner_id = new.owner_id;
    end if;
    select plan_until into pro_end from public.profiles where id = new.owner_id and plan = 'pro';
    best_end := greatest(claim_end, pro_end);
    if best_end > now() and best_end > coalesce(new.featured_until, '-infinity'::timestamptz) then
      new.featured_until := best_end;
    end if;
    new.reviewed_at := coalesce(new.reviewed_at, now());
  end if;

  new.updated_at := now();
  return new;
end; $$;

drop trigger if exists listings_guard on public.listings;
create trigger listings_guard before insert or update on public.listings
  for each row execute function public.listings_guard();

-- Who can SEE listings (replaces the old read rules)
do $$ declare r record; begin
  for r in select policyname from pg_policies
           where schemaname = 'public' and tablename = 'listings' and cmd = 'SELECT' loop
    execute format('drop policy %I on public.listings', r.policyname);
  end loop;
end $$;
create policy "Public sees approved listings" on public.listings for select to anon, authenticated
  using (status = 'active' and approval = 'approved');
create policy "Owners see own listings" on public.listings for select to authenticated
  using (owner_id = auth.uid());
create policy "Admins see all listings" on public.listings for select to authenticated
  using (public.my_role() = 'admin');

drop policy if exists "Admins manage listings" on public.listings;
create policy "Admins manage listings" on public.listings for all to authenticated
  using (public.my_role() = 'admin') with check (public.my_role() = 'admin');

-- Admin can read all renter messages
drop policy if exists "Admins read inquiries" on public.inquiries;
create policy "Admins read inquiries" on public.inquiries for select to authenticated
  using (public.my_role() = 'admin');


-- ---------------------------------------------------------------------
-- 4. TAHANAN PRO payment requests (GCash, confirmed by admin)
-- ---------------------------------------------------------------------
create table if not exists public.pro_requests (
  id          uuid primary key default gen_random_uuid(),
  owner_id    uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  amount      numeric not null default 0,
  days        int not null default 30,
  reference   text not null check (length(reference) between 4 and 60),
  status      text not null default 'pending' check (status in ('pending','approved','rejected')),
  created_at  timestamptz not null default now(),
  reviewed_at timestamptz
);
create unique index if not exists pro_requests_one_pending on public.pro_requests(owner_id) where status = 'pending';
alter table public.pro_requests enable row level security;

-- Price and days always come from settings (owners can't change them)
create or replace function public.pro_requests_guard()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if coalesce(public.my_role(),'') <> 'admin' then
    if tg_op <> 'INSERT' then raise exception 'Only admins can change payment requests'; end if;
    if coalesce((select role from public.profiles where id = auth.uid()), '') <> 'owner' then
      raise exception 'Only property owners can subscribe to Pro';
    end if;
    new.owner_id    := auth.uid();
    new.status      := 'pending';
    new.reviewed_at := null;
    new.amount      := coalesce(nullif(public.setting('pro_price'), '')::numeric, 199);
    new.days        := coalesce(nullif(public.setting('pro_days'), '')::int, 30);
  end if;
  return new;
end; $$;
drop trigger if exists pro_requests_guard on public.pro_requests;
create trigger pro_requests_guard before insert or update on public.pro_requests
  for each row execute function public.pro_requests_guard();

drop policy if exists "Owners request Pro" on public.pro_requests;
create policy "Owners request Pro" on public.pro_requests for insert to authenticated
  with check (owner_id = auth.uid());
drop policy if exists "Owners see own Pro requests" on public.pro_requests;
create policy "Owners see own Pro requests" on public.pro_requests for select to authenticated
  using (owner_id = auth.uid() or public.my_role() = 'admin');
drop policy if exists "Admins manage Pro requests" on public.pro_requests;
create policy "Admins manage Pro requests" on public.pro_requests for all to authenticated
  using (public.my_role() = 'admin') with check (public.my_role() = 'admin');
grant select, insert, update, delete on public.pro_requests to authenticated;


-- ---------------------------------------------------------------------
-- 5. REPORTS (renters flag scams or fake listings)
-- ---------------------------------------------------------------------
create table if not exists public.reports (
  id          uuid primary key default gen_random_uuid(),
  listing_id  uuid not null references public.listings(id) on delete cascade,
  reporter_id uuid default auth.uid() references public.profiles(id) on delete set null,
  reason      text not null check (length(reason) <= 120),
  details     text check (length(details) <= 1000),
  status      text not null default 'open' check (status in ('open','resolved')),
  created_at  timestamptz not null default now()
);
alter table public.reports enable row level security;
drop policy if exists "Users send reports" on public.reports;
create policy "Users send reports" on public.reports for insert to authenticated
  with check (reporter_id = auth.uid() and status = 'open');
drop policy if exists "Admins manage reports" on public.reports;
create policy "Admins manage reports" on public.reports for all to authenticated
  using (public.my_role() = 'admin') with check (public.my_role() = 'admin');
grant select, insert, update, delete on public.reports to authenticated;


-- ---------------------------------------------------------------------
-- 6. ADMIN TOOLS
-- ---------------------------------------------------------------------
-- All users with email, last login, and activity
drop function if exists public.admin_users();
create function public.admin_users()
returns table(id uuid, full_name text, phone text, role text, plan text, plan_until timestamptz,
              email text, created_at timestamptz, last_sign_in_at timestamptz,
              listings int, messages_sent int)
language sql stable security definer set search_path = public as $$
  select p.id, p.full_name::text, p.phone::text, p.role::text, p.plan::text, p.plan_until,
         u.email::text, u.created_at, u.last_sign_in_at,
         (select count(*)::int from public.listings l where l.owner_id = p.id),
         (select count(*)::int from public.inquiries i where i.renter_id = p.id)
  from public.profiles p
  join auth.users u on u.id = p.id
  where coalesce(public.my_role(),'') = 'admin'
  order by u.created_at desc
$$;
revoke execute on function public.admin_users() from public, anon;
grant execute on function public.admin_users() to authenticated;

-- Traffic per listing (last N days)
drop function if exists public.admin_listing_stats(int);
create function public.admin_listing_stats(p_days int default 30)
returns table(listing_id uuid, impressions int, views int, contacts int)
language sql stable security definer set search_path = public as $$
  select e.listing_id,
         count(*) filter (where e.event = 'impression')::int,
         count(*) filter (where e.event = 'view')::int,
         count(*) filter (where e.event = 'contact')::int
  from public.listing_events e
  where e.created_at > now() - make_interval(days => p_days)
    and coalesce(public.my_role(),'') = 'admin'
  group by e.listing_id
$$;
revoke execute on function public.admin_listing_stats(int) from public, anon;
grant execute on function public.admin_listing_stats(int) to authenticated;

-- Change a user's role
create or replace function public.admin_set_role(p_user uuid, p_role text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if coalesce(public.my_role(),'') <> 'admin' then raise exception 'Admins only'; end if;
  if p_role not in ('renter','owner','admin') then raise exception 'Invalid role'; end if;
  if p_user = auth.uid() and p_role <> 'admin' then
    raise exception 'You cannot remove your own admin access here';
  end if;
  update public.profiles set role = p_role where id = p_user;
end; $$;
revoke execute on function public.admin_set_role(uuid, text) from public, anon;
grant execute on function public.admin_set_role(uuid, text) to authenticated;

-- Give Pro for N days (adds to remaining time). 0 = remove Pro.
create or replace function public.admin_set_plan(p_user uuid, p_days int)
returns void language plpgsql security definer set search_path = public as $$
declare old_until timestamptz; new_until timestamptz;
begin
  if coalesce(public.my_role(),'') <> 'admin' then raise exception 'Admins only'; end if;
  select plan_until into old_until from public.profiles where id = p_user;
  if p_days > 0 then
    new_until := greatest(coalesce(old_until, now()), now()) + make_interval(days => p_days);
    update public.profiles set plan = 'pro', plan_until = new_until where id = p_user;
    update public.listings set featured_until = new_until
      where owner_id = p_user and approval = 'approved'
        and (featured_until is null or featured_until < new_until);
  else
    update public.profiles set plan = 'free', plan_until = null where id = p_user;
    if old_until is not null then
      update public.listings set featured_until = null
        where owner_id = p_user and featured_until = old_until;
    end if;
  end if;
end; $$;
revoke execute on function public.admin_set_plan(uuid, int) from public, anon;
grant execute on function public.admin_set_plan(uuid, int) to authenticated;

-- Approve or reject a GCash payment
create or replace function public.admin_review_pro(p_id uuid, p_approve boolean)
returns void language plpgsql security definer set search_path = public as $$
declare r public.pro_requests;
begin
  if coalesce(public.my_role(),'') <> 'admin' then raise exception 'Admins only'; end if;
  select * into r from public.pro_requests where id = p_id for update;
  if r.id is null or r.status <> 'pending' then raise exception 'Request not found or already reviewed'; end if;
  update public.pro_requests
     set status = case when p_approve then 'approved' else 'rejected' end, reviewed_at = now()
   where id = p_id;
  if p_approve then perform public.admin_set_plan(r.owner_id, r.days); end if;
end; $$;
revoke execute on function public.admin_review_pro(uuid, boolean) from public, anon;
grant execute on function public.admin_review_pro(uuid, boolean) to authenticated;

-- Refresh the API so the website sees the new tables right away
notify pgrst, 'reload schema';
