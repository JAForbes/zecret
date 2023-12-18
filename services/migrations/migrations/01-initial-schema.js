export const name = 'Initial Schema'

export const teardown = async (sql) => {
	await sql`
		drop role zecret_api;
	`.catch(() => {})
}
export const action = async (sql, { roles }) => {
	await sql`
		set role ${sql.unsafe(roles.migration)}
	`
	const service = sql.unsafe(roles.service)

	await sql`
		create extension citext schema public;
	`

	await sql`
		create schema zecret;
	`
	await sql`
		grant usage on schema zecret to ${service};
	`

	await sql`
		create table zecret.meta(
			created_at timestamptz not null default now()
			, updated_at timestamptz not null default now()
			, deleted_at timestamptz NULL
		);
	`
	await sql`create table zecret.user (
		user_id uuid primary key default gen_random_uuid()
		,github_user_id public.citext null unique
		,like zecret.meta including defaults
	);`

	await sql`
		create or replace function zecret.get_active_user()
		returns uuid
		as $$
			with xs as (
				select current_setting('zecret.user_id', true) as v
			)
			
			select 
				(case v
					when '' then null
					else v
				end)::uuid
			from xs;
		$$
		language sql
		set search_path = ''
		security definer
		;
	`

	await sql`
		create table zecret.org(
				organization_name public.citext primary key
				,primary_owner_id uuid not null references zecret.user(user_id) default zecret.get_active_user()
				,like zecret.meta including defaults
		);
	`

	await sql`
		create or replace function zecret.get_active_org()
		returns public.citext
		as $$
			with xs as (
				select current_setting('zecret.org', true) as v
			)
			
			select 
				(case v
					when '' then null
					else v
				end)::public.citext
			from xs;
		$$
		language sql
		set search_path = ''
		security definer
		;
	`

	await sql`
		grant execute on function zecret.get_active_user to ${service};
	`

	await sql`
		grant execute on function zecret.get_active_org to ${service};
	`

	await sql`
		create table zecret.group(
				group_name public.citext not null
				,organization_name public.citext
						not null
						references zecret.org(organization_name)
						on update cascade
						on delete cascade
						deferrable initially deferred
				, primary key (group_name, organization_name)
				, like zecret.meta including defaults
		);
	`

	await sql`
		create table zecret.org_user(
			organization_name public.citext not null
				references zecret.org(organization_name)
				on update cascade
				on delete cascade
				deferrable initially deferred
			,user_id uuid not null
				references zecret.user(user_id)
				on update cascade
				on delete cascade
				deferrable initially deferred
			, primary key (organization_name, user_id)
			, like zecret.meta including defaults
		);
	`

	await sql`
		create table zecret.org_admin(
			organization_name public.citext not null
				references zecret.org(organization_name)
				on update cascade
				on delete cascade
				deferrable initially deferred
			,user_id uuid not null
				references zecret.user(user_id)
				on update cascade
				on delete cascade
				deferrable initially deferred
			, primary key (organization_name, user_id)
			, like zecret.meta including defaults
		)
	`

	await sql`
		create table zecret.group_user(
			group_name public.citext not null
			, organization_name public.citext not null
			, user_id uuid references zecret.user(user_id)
			, primary key (group_name, user_id)
			, like zecret.meta including defaults
			, constraint fk_org_and_group foreign key(organization_name, group_name)
				references zecret.group(organization_name, group_name)
				on update cascade
				on delete cascade
				deferrable initially deferred
			, constraint fk_org_and_user foreign key(organization_name, user_id)
				references zecret.org_user(organization_name, user_id)
				on update cascade
				on delete cascade
				deferrable initially deferred
		);
	`

	await sql`
		create table zecret.grant_level(
			grant_level public.citext primary key
		);
	`

	await sql`
		insert into zecret.grant_level (grant_level) values ('read'), ('write');
	`

	await sql`
		create table zecret.grant_user(
			path public.citext not null
			, organization_name public.citext null
			, user_id uuid null
			, grant_level public.citext not null
				references zecret.grant_level(grant_level)
			, like zecret.meta including defaults

			, primary key (organization_name, path, grant_level, user_id)

			, constraint fk_org_and_user foreign key(organization_name, user_id)
				references zecret.org_user(organization_name, user_id)
				on update cascade
				on delete cascade
				deferrable initially deferred
		);
	`

	await sql`
		create table zecret.grant_group(
			path public.citext not null
			, organization_name public.citext null
			, group_name public.citext null
			, grant_level public.citext not null
				references zecret.grant_level(grant_level)
			, like zecret.meta including defaults

			, primary key (organization_name, path, grant_level, group_name)

			, constraint fk_org_and_group foreign key(organization_name, group_name)
				references zecret.group(organization_name, group_name)
				on update cascade
				on delete cascade
				deferrable initially deferred
		);
	`

	await sql`
		create view zecret.grant as
			select organization_name, path, null::uuid as user_id, group_name, grant_level, created_at, updated_at, deleted_at
			from zecret.grant_group
			union all
			select organization_name, path, user_id, null::public.citext as group_name, grant_level, created_at, updated_at, deleted_at
			from zecret.grant_user
	`

	await sql`
		create table zecret.server_public_key(
			server_public_key_id text primary key
			, server_public_key_pkcs8 text unique
			, like zecret.meta including defaults
		);
	`

	await sql`
		create table zecret.secret(
			path public.citext not null
			, organization_name public.citext not null
				references zecret.org(organization_name)
				on update cascade
				on delete cascade
				deferrable initially deferred
			, key public.citext not null
			, value text not null
			, iv text not null
			, symmetric_secret text not null
			, server_public_key_id text not null references zecret.server_public_key(server_public_key_id)
			, primary key (organization_name, path, key, server_public_key_id)
			, like zecret.meta including defaults
		);
	`

	await sql`
		grant select on zecret.grant_level to ${service}
	`
	for (let [table, grants] of [
		['zecret.user', 'select, insert, update'],
		['zecret.org', 'select, insert, update'],
		['zecret.group', 'select, insert, update, delete'],
		['zecret.org_user', 'select, insert, update, delete'],
		['zecret.org_admin', 'select, insert, update, delete'],
		['zecret.group_user', 'select, insert, update, delete'],
		['zecret.grant_user', 'select, insert, update, delete'],
		['zecret.grant_group', 'select, insert, update, delete'],
		['zecret.secret', 'select, insert, update'],
		['zecret.server_public_key', 'select, insert, update']
	]) {
		await sql`
			alter table ${sql(table)} 
				enable row level security
		`

		await sql`
			grant ${sql.unsafe(grants)} on ${sql(table)} to ${service}
		`
	}

	await sql`
		create role zecret_api with login password 'zecret';
	`

	await sql`
		grant ${service} to zecret_api;
	`
}
