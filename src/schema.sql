create extension citext;
create schema zecret;

-- just for now while hacking away at this
create role zecret_api with login password 'zecret' noinherit;
grant usage on schema zecret to zecret_api;

drop table zecret.meta;
create table zecret.meta(
	created_at timestamptz not null default now()
	
	, updated_at timestamptz not null default now()
	
	, deleted_at timestamptz NULL
);


drop table if exists zecret.user;
create table zecret.user (
	user_id uuid primary key default gen_random_uuid()
	
	,github_user_id citext null unique
	
	,like zecret.meta
);


drop table if exists zecret.org;
create table zecret.org(
	organization_name citext primary key

	,like zecret.meta
);

drop table if exists zecret.group cascade;
create table zecret.group(
	group_name citext not null
	
	,organization_name citext 
		not null 
		references zecret.org(organization_name)
		on update CASCADE
		on delete CASCADE
		deferrable initially deferred
		
	, primary key (group_name, organization_name)
	
	, like zecret.meta
);

create table zecret.org_user(
	organization_name citext not null
		references zecret.org(organization_name)
		on update CASCADE
		on delete CASCADE
		deferrable initially deferred
	
	,user_id uuid not null
		references zecret.user(user_id)
		on update CASCADE
		on delete CASCADE
		deferrable initially deferred
	
	, primary key (organization_name, user_id)
	 
	
	, like zecret.meta
);

drop table zecret.group_user;
create table zecret.group_user(
	group_name citext not null 
		
	, organization_name citext not null 
	
	, user_id uuid references zecret.user(user_id)
	
	, primary key (group_name, user_id)
	, like zecret.meta
	
	, constraint fk_org_and_group foreign key(organization_name, group_name)
		references zecret.group(organization_name, group_name)
		on update CASCADE
		on delete CASCADE
		deferrable initially deferred

	, constraint fk_org_and_user foreign key(organization_name, user_id)
		references zecret.org_user(organization_name, user_id)
		on update CASCADE
		on delete CASCADE
		deferrable initially deferred
);

create table zecret.grant_level(
	grant_level citext primary key
);
insert into zecret.grant_level (grant_level) values ('read'), ('write'), ('grant');

drop table if exists zecret.grant;
create table zecret.grant(
	
	path citext not null
	
	, organization_name citext null
	
	, group_name citext null 
	
	, user_id uuid null 

	, level citext not null 
		references zecret.grant_level(grant_level)
	
	, primary key (organization_name, path, level, group_name, user_id)
	
	, like zecret.meta
	
	, constraint either_user_or_group 
		check ( 
			(group_name is null) <> (user_id is null)
		)
		
	, constraint fk_org_and_group foreign key(organization_name, group_name)
		references zecret.group(organization_name, group_name)
		on update CASCADE
		on delete CASCADE
		deferrable initially deferred
		
	, constraint fk_org_and_user foreign key(organization_name, user_id)
		references zecret.org_user(organization_name, user_id)
		on update CASCADE
		on delete CASCADE
		deferrable initially deferred
);


create table zecret.secret(
	path citext not null
	
	, organization_name citext not null
		references zecret.org(organization_name)
		on update CASCADE
		on delete CASCADE
		deferrable initially deferred
	
	, key citext not null 
	
	, value text not null
	
	, primary key (organization_name, path, key)
	
	, like zecret.meta
);