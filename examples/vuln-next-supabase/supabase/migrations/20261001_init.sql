create table public.profiles (
  id uuid primary key references auth.users,
  email text,
  phone text
);

create table public.posts (
  id bigint generated always as identity primary key,
  author uuid references public.profiles,
  body text
);
alter table public.posts enable row level security;
create policy "anyone" on public.posts for all using (true);
