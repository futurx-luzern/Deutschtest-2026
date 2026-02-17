-- Supabase schema for minimal online test platform
create extension if not exists pgcrypto;

create table if not exists app_settings (
  id boolean primary key default true,
  admin_username text not null unique,
  admin_pin_hash text not null,
  platform_link text not null default 'https://your-project.vercel.app'
);

insert into app_settings (id, admin_username, admin_pin_hash)
values (true, 'Admin', crypt('CHANGE_ME_ADMIN_PIN', gen_salt('bf')))
on conflict (id) do nothing;

create table if not exists participants (
  id uuid primary key default gen_random_uuid(),
  pseudonym_id text not null unique,
  display_name text,
  pin_hash text not null,
  initial_pin text not null,
  active boolean not null default true,
  auto_delete_enabled boolean not null default false,
  auto_delete_days integer not null default 90,
  delete_after timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists test_assignments (
  id uuid primary key default gen_random_uuid(),
  participant_id uuid not null references participants(id) on delete cascade,
  test_key text not null check (test_key in ('deutsch','mathe','daz')),
  status text not null default 'not_started' check (status in ('not_started','in_progress','completed')),
  locked boolean not null default false,
  current_page integer not null default 0,
  progress_percent integer not null default 0,
  state jsonb,
  last_activity_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(participant_id, test_key)
);

create table if not exists app_sessions (
  token_hash text primary key,
  role text not null check (role in ('admin', 'participant')),
  participant_id uuid references participants(id) on delete cascade,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);

create or replace function touch_updated_at() returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

drop trigger if exists participants_touch on participants;
drop trigger if exists assignments_touch on test_assignments;
create trigger participants_touch before update on participants for each row execute function touch_updated_at();
create trigger assignments_touch before update on test_assignments for each row execute function touch_updated_at();

create or replace function maybe_lock_inactive_assignments() returns void as $$
begin
  update test_assignments
  set locked = true
  where status = 'in_progress'
    and locked = false
    and last_activity_at is not null
    and last_activity_at < now() - interval '1 hour';
end;
$$ language plpgsql security definer;

create or replace function create_app_session(p_role text, p_participant_id uuid default null)
returns text
language plpgsql
security definer
as $$
declare
  v_token text;
  v_hash text;
begin
  v_token := encode(gen_random_bytes(32), 'hex');
  v_hash := encode(digest(v_token, 'sha256'), 'hex');
  insert into app_sessions(token_hash, role, participant_id, expires_at)
  values (
    v_hash,
    p_role,
    p_participant_id,
    now() + case when p_role = 'admin' then interval '12 hours' else interval '30 days' end
  );
  return v_token;
end;
$$;

create or replace function assert_admin(p_session_token text) returns void
language plpgsql security definer as $$
declare
  v_hash text;
  v_exists boolean;
begin
  if p_session_token is null or length(p_session_token) < 20 then
    raise exception 'Admin-Session ungültig';
  end if;

  v_hash := encode(digest(p_session_token, 'sha256'), 'hex');
  select exists (
    select 1
    from app_sessions s
    where s.token_hash = v_hash
      and s.role = 'admin'
      and s.expires_at > now()
  ) into v_exists;

  if not v_exists then
    raise exception 'Admin-Session abgelaufen oder ungültig';
  end if;
end;
$$;

create or replace function assert_participant(p_session_token text) returns uuid
language plpgsql security definer as $$
declare
  v_hash text;
  v_participant_id uuid;
begin
  if p_session_token is null or length(p_session_token) < 20 then
    raise exception 'Teilnehmenden-Session ungültig';
  end if;

  v_hash := encode(digest(p_session_token, 'sha256'), 'hex');
  select s.participant_id
  into v_participant_id
  from app_sessions s
  join participants p on p.id = s.participant_id
  where s.token_hash = v_hash
    and s.role = 'participant'
    and s.expires_at > now()
    and p.active = true;

  if v_participant_id is null then
    raise exception 'Teilnehmenden-Session abgelaufen oder ungültig';
  end if;

  return v_participant_id;
end;
$$;

create or replace function app_login(p_username text, p_pin text)
returns jsonb
language plpgsql
security definer
as $$
declare
  s app_settings;
  p participants;
  v_session_token text;
begin
  delete from app_sessions where expires_at <= now();

  select * into s from app_settings where id = true;
  if lower(p_username) = lower(s.admin_username) and crypt(p_pin, s.admin_pin_hash) = s.admin_pin_hash then
    v_session_token := create_app_session('admin', null);
    return jsonb_build_object('ok', true, 'role', 'admin', 'session_token', v_session_token);
  end if;

  select * into p from participants where pseudonym_id = p_username and active = true;
  if p.id is null then
    return jsonb_build_object('ok', false, 'message', 'Unbekannter Zugang');
  end if;
  if crypt(p_pin, p.pin_hash) <> p.pin_hash then
    return jsonb_build_object('ok', false, 'message', 'Falsches Passwort/PIN');
  end if;

  v_session_token := create_app_session('participant', p.id);
  return jsonb_build_object(
    'ok', true,
    'role', 'participant',
    'participant_id', p.id,
    'pseudonym_id', p.pseudonym_id,
    'session_token', v_session_token
  );
end;
$$;

grant execute on function app_login(text,text) to anon, authenticated;

create or replace function app_logout(p_session_token text)
returns void
language plpgsql
security definer
as $$
begin
  delete from app_sessions where token_hash = encode(digest(p_session_token, 'sha256'), 'hex');
end;
$$;

grant execute on function app_logout(text) to anon, authenticated;

create or replace function admin_create_participant(
  p_session_token text,
  p_pseudonym_id text,
  p_display_name text,
  p_pin text,
  p_auto_delete_enabled boolean,
  p_auto_delete_days integer,
  p_tests text[]
) returns jsonb
language plpgsql security definer as $$
declare
  v_id uuid;
  t text;
begin
  perform assert_admin(p_session_token);

  insert into participants(pseudonym_id, display_name, pin_hash, initial_pin, auto_delete_enabled, auto_delete_days, delete_after)
  values (
    p_pseudonym_id,
    p_display_name,
    crypt(p_pin, gen_salt('bf')),
    p_pin,
    coalesce(p_auto_delete_enabled, false),
    greatest(coalesce(p_auto_delete_days, 90), 1),
    case when coalesce(p_auto_delete_enabled, false) then now() + make_interval(days => greatest(coalesce(p_auto_delete_days,90),1)) else null end
  ) returning id into v_id;

  foreach t in array p_tests loop
    insert into test_assignments(participant_id, test_key) values (v_id, t) on conflict do nothing;
  end loop;

  return jsonb_build_object('ok', true, 'participant_id', v_id);
end;
$$;

create or replace function admin_list_participants(p_session_token text)
returns table(id uuid, pseudonym_id text, display_name text, created_at timestamptz)
language plpgsql security definer as $$
begin
  perform assert_admin(p_session_token);
  return query
  select p.id, p.pseudonym_id, p.display_name, p.created_at
  from participants p
  where p.active = true
  order by p.created_at desc;
end;
$$;

create or replace function admin_toggle_lock_for_participant(p_session_token text, p_participant_id uuid)
returns void
language plpgsql security definer as $$
begin
  perform assert_admin(p_session_token);
  update test_assignments set locked = not locked where participant_id = p_participant_id;
end;
$$;

create or replace function admin_delete_participant(p_session_token text, p_participant_id uuid)
returns void
language plpgsql security definer as $$
begin
  perform assert_admin(p_session_token);
  delete from participants where id = p_participant_id;
end;
$$;

create or replace function admin_get_credentials_pdf_payload(p_session_token text, p_participant_id uuid)
returns jsonb
language plpgsql security definer as $$
declare
  p participants;
  test_names text[];
  platform text;
begin
  perform assert_admin(p_session_token);
  select * into p from participants where id = p_participant_id;
  if p.id is null then return jsonb_build_object('ok', false, 'message', 'Teilnehmende nicht gefunden'); end if;

  select array_agg(case test_key
    when 'deutsch' then 'Einstufungstest Deutsch'
    when 'mathe' then 'Einstufungstest Mathe'
    when 'daz' then 'Einstufungstest DAZ'
    else test_key end order by test_key)
  into test_names
  from test_assignments
  where participant_id = p.id;

  select platform_link into platform from app_settings where id = true;

  return jsonb_build_object(
    'ok', true,
    'payload', jsonb_build_object(
      'platform_link', platform,
      'username', p.pseudonym_id,
      'pin', p.initial_pin,
      'test_names', coalesce(test_names, array[]::text[])
    )
  );
end;
$$;

create or replace function admin_export_results_json(p_session_token text, p_participant_id uuid)
returns jsonb
language plpgsql security definer as $$
begin
  perform assert_admin(p_session_token);
  return (
    select jsonb_build_object(
      'participant', jsonb_build_object('id', p.id, 'pseudonym_id', p.pseudonym_id, 'display_name', p.display_name),
      'assignments', coalesce(jsonb_agg(jsonb_build_object(
        'assignment_id', a.id,
        'test_key', a.test_key,
        'status', a.status,
        'progress_percent', a.progress_percent,
        'state', a.state,
        'last_activity_at', a.last_activity_at,
        'updated_at', a.updated_at
      ) order by a.created_at desc), '[]'::jsonb)
    )
    from participants p
    left join test_assignments a on a.participant_id = p.id
    where p.id = p_participant_id
    group by p.id
  );
end;
$$;

create or replace function admin_cleanup_expired_accounts(p_session_token text)
returns integer
language plpgsql security definer as $$
declare
  deleted_count integer;
begin
  perform assert_admin(p_session_token);
  delete from participants
  where auto_delete_enabled = true and delete_after is not null and delete_after <= now();
  get diagnostics deleted_count = row_count;
  return deleted_count;
end;
$$;

create or replace function participant_list_assignments(p_session_token text)
returns table(id uuid, test_key text, status text, locked boolean, last_activity_at timestamptz, progress_percent integer, created_at timestamptz)
language plpgsql security definer as $$
declare
  v_participant_id uuid;
begin
  perform maybe_lock_inactive_assignments();
  v_participant_id := assert_participant(p_session_token);

  return query
  select a.id, a.test_key, a.status, a.locked, a.last_activity_at, a.progress_percent, a.created_at
  from test_assignments a
  where a.participant_id = v_participant_id
  order by a.created_at desc;
end;
$$;

create or replace function participant_get_assignment(p_session_token text, p_assignment_id uuid)
returns jsonb
language plpgsql security definer as $$
declare
  v_participant_id uuid;
  a test_assignments;
begin
  perform maybe_lock_inactive_assignments();
  v_participant_id := assert_participant(p_session_token);

  select * into a
  from test_assignments
  where id = p_assignment_id and participant_id = v_participant_id;

  if a.id is null then
    return jsonb_build_object('ok', false, 'message', 'Testzuweisung nicht gefunden');
  end if;

  return jsonb_build_object(
    'ok', true,
    'assignment', jsonb_build_object(
      'id', a.id,
      'test_key', a.test_key,
      'status', a.status,
      'locked', a.locked,
      'state', a.state,
      'current_page', a.current_page,
      'progress_percent', a.progress_percent
    )
  );
end;
$$;

create or replace function participant_save_progress(
  p_session_token text,
  p_assignment_id uuid,
  p_state jsonb,
  p_current_page integer,
  p_progress_percent integer,
  p_status text
) returns jsonb
language plpgsql security definer as $$
declare
  v_participant_id uuid;
  v_rows integer;
begin
  v_participant_id := assert_participant(p_session_token);

  update test_assignments
  set state = p_state,
      current_page = greatest(coalesce(p_current_page, 0), 0),
      progress_percent = least(greatest(coalesce(p_progress_percent, 0), 0), 100),
      status = case when p_status in ('not_started','in_progress','completed') then p_status else status end,
      locked = false,
      last_activity_at = now()
  where id = p_assignment_id
    and participant_id = v_participant_id
    and locked = false;

  get diagnostics v_rows = row_count;

  if v_rows = 0 then
    return jsonb_build_object('ok', false, 'message', 'Speichern nicht möglich (gesperrt oder nicht gefunden)');
  end if;

  return jsonb_build_object('ok', true);
end;
$$;

grant execute on function admin_create_participant(text,text,text,text,boolean,integer,text[]) to anon, authenticated;
grant execute on function admin_list_participants(text) to anon, authenticated;
grant execute on function admin_toggle_lock_for_participant(text,uuid) to anon, authenticated;
grant execute on function admin_delete_participant(text,uuid) to anon, authenticated;
grant execute on function admin_get_credentials_pdf_payload(text,uuid) to anon, authenticated;
grant execute on function admin_export_results_json(text,uuid) to anon, authenticated;
grant execute on function admin_cleanup_expired_accounts(text) to anon, authenticated;
grant execute on function participant_list_assignments(text) to anon, authenticated;
grant execute on function participant_get_assignment(text,uuid) to anon, authenticated;
grant execute on function participant_save_progress(text,uuid,jsonb,integer,integer,text) to anon, authenticated;

alter table participants enable row level security;
alter table test_assignments enable row level security;
alter table app_sessions enable row level security;

drop policy if exists participant_select_own on test_assignments;
drop policy if exists participant_update_own on test_assignments;

create policy deny_all_participants on participants for all using (false) with check (false);
create policy deny_all_assignments on test_assignments for all using (false) with check (false);
create policy deny_all_sessions on app_sessions for all using (false) with check (false);
