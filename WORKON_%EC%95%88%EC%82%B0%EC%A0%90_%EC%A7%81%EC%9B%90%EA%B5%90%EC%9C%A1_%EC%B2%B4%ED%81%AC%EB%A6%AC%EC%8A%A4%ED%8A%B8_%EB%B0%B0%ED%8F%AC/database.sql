-- WORKON 안산점 · Supabase SQL Editor에서 한 번 실행
-- 실행 전 프로젝트 Auth 이메일 인증 및 비밀번호 정책을 설정하세요.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
 id uuid primary key references auth.users(id) on delete cascade,
 full_name text not null check (char_length(full_name) between 2 and 40),
 phone text not null check (char_length(phone) between 9 and 20),
 job text not null check (job in ('데스크','서원','외곽','포스트','셔틀','드라이버','가이드')),
 role text not null default 'employee' check (role in ('employee','admin')),
 status text not null default 'pending' check (status in ('pending','approved','suspended')),
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now()
);

create or replace function public.create_staff_profile() returns trigger
language plpgsql security definer set search_path = '' as $$
declare j text;
begin
  j:=new.raw_user_meta_data->>'job';
  if j not in ('데스크','서원','외곽','포스트','셔틀','드라이버','가이드') then
    raise exception 'Invalid position';
  end if;
  insert into public.profiles(id,full_name,phone,job,role,status)
  values(new.id,trim(new.raw_user_meta_data->>'full_name'),trim(new.raw_user_meta_data->>'phone'),j,'employee','pending');
  return new;
end; $$;
drop trigger if exists on_staff_created on auth.users;
create trigger on_staff_created after insert on auth.users for each row execute function public.create_staff_profile();

create or replace function public.is_staff_admin() returns boolean
language sql stable security definer set search_path = '' as $$
 select exists(select 1 from public.profiles where id=(select auth.uid()) and role='admin' and status='approved')
$$;
create or replace function public.is_approved_staff() returns boolean
language sql stable security definer set search_path = '' as $$
 select exists(select 1 from public.profiles where id=(select auth.uid()) and status='approved')
$$;

create table if not exists public.training_completions (
 id uuid primary key default gen_random_uuid(),
 user_id uuid not null references public.profiles(id) on delete cascade,
 course_version text not null check (char_length(course_version) between 4 and 32),
 job text not null check (job in ('데스크','서원','외곽','포스트','셔틀','드라이버','가이드')),
 answers jsonb not null,
 score integer not null check (score=3),
 acknowledged boolean not null check (acknowledged=true),
 completed_at timestamptz not null default now()
);
create index if not exists ix_training_user on public.training_completions(user_id,completed_at desc);

create table if not exists public.checklist_submissions (
 id uuid primary key default gen_random_uuid(),
 user_id uuid not null references public.profiles(id) on delete cascade,
 work_date date not null,
 job text not null check (job in ('데스크','서원','외곽','포스트','셔틀','드라이버','가이드')),
 answers jsonb not null check (jsonb_typeof(answers)='object'),
 total_count integer not null check (total_count between 1 and 30),
 checked_count integer not null check (checked_count between 0 and total_count),
 submitted_at timestamptz not null default now(),
 unique(user_id,work_date)
);
create index if not exists ix_check_date on public.checklist_submissions(work_date desc,submitted_at desc);

-- submitted_at/completed_at, 신원, 포지션 등은 서버 값으로 고정합니다.
create or replace function public.check_training_insert() returns trigger
language plpgsql security definer set search_path = '' as $$
declare expected_job text;
begin
  select job into expected_job from public.profiles where id=(select auth.uid()) and status='approved';
  if expected_job is null or new.user_id<>(select auth.uid()) or new.job<>expected_job then
    raise exception 'Unauthorized training submission';
  end if;
  if new.answers <> '[1,1,1]'::jsonb or new.score<>3 or not new.acknowledged then
    raise exception 'Training assessment must be passed';
  end if;
  new.completed_at:=now();
  return new;
end; $$;
drop trigger if exists training_insert_guard on public.training_completions;
create trigger training_insert_guard before insert on public.training_completions for each row execute function public.check_training_insert();

create or replace function public.check_checklist_insert() returns trigger
language plpgsql security definer set search_path = '' as $$
declare expected_job text; n integer; total integer;
begin
  select job into expected_job from public.profiles where id=(select auth.uid()) and status='approved';
  if expected_job is null or new.user_id<>(select auth.uid()) or new.job<>expected_job then
    raise exception 'Unauthorized checklist submission';
  end if;
  if new.work_date < ((now() at time zone 'Asia/Seoul')::date - 30)
     or new.work_date > ((now() at time zone 'Asia/Seoul')::date + 1) then
    raise exception 'Work date is outside allowed window';
  end if;
  if exists(select 1 from jsonb_each(new.answers) as x where jsonb_typeof(x.value)<>'boolean') then
    raise exception 'Checklist answers must be booleans';
  end if;
  select count(*),count(*) filter (where value='true'::jsonb) into total,n from jsonb_each(new.answers);
  if total<>new.total_count or n<>new.checked_count then
    raise exception 'Checklist counts are invalid';
  end if;
  new.submitted_at:=now();
  return new;
end; $$;
drop trigger if exists checklist_insert_guard on public.checklist_submissions;
create trigger checklist_insert_guard before insert on public.checklist_submissions for each row execute function public.check_checklist_insert();

alter table public.profiles enable row level security;
alter table public.training_completions enable row level security;
alter table public.checklist_submissions enable row level security;

drop policy if exists profile_read on public.profiles;
create policy profile_read on public.profiles for select to authenticated using (id=(select auth.uid()) or (select public.is_staff_admin()));
drop policy if exists profile_admin_update on public.profiles;
create policy profile_admin_update on public.profiles for update to authenticated using ((select public.is_staff_admin())) with check ((select public.is_staff_admin()));

drop policy if exists training_read on public.training_completions;
create policy training_read on public.training_completions for select to authenticated using (user_id=(select auth.uid()) or (select public.is_staff_admin()));
drop policy if exists training_insert on public.training_completions;
create policy training_insert on public.training_completions for insert to authenticated with check ((select public.is_approved_staff()) and user_id=(select auth.uid()));

drop policy if exists checklist_read on public.checklist_submissions;
create policy checklist_read on public.checklist_submissions for select to authenticated using (user_id=(select auth.uid()) or (select public.is_staff_admin()));
drop policy if exists checklist_insert on public.checklist_submissions;
create policy checklist_insert on public.checklist_submissions for insert to authenticated with check ((select public.is_approved_staff()) and user_id=(select auth.uid()));

-- 명시적으로 UPDATE/DELETE 정책을 만들지 않아 직원이 제출 이력을 고칠 수 없습니다.
revoke all on public.profiles,public.training_completions,public.checklist_submissions from anon;
grant select on public.profiles,public.training_completions,public.checklist_submissions to authenticated;
grant update(status,job,full_name,phone) on public.profiles to authenticated;
grant insert on public.training_completions,public.checklist_submissions to authenticated;
grant execute on function public.is_staff_admin() to authenticated;
grant execute on function public.is_approved_staff() to authenticated;

-- 최초 관리자 계정은 일반 회원가입 및 이메일 인증 후 다음을 SQL Editor에서 실행합니다.
-- 확인된 본인 이메일로 교체해 실행하세요 (관리자 계정 생성 기능은 외부에 노출되지 않음).
-- update public.profiles set role='admin',status='approved'
-- where id=(select id from auth.users where email='YOUR_ADMIN_EMAIL@example.com');
