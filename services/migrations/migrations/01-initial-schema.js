export const name = "Initial Schema"

export const teardown = async (sql) => {
	await sql`
		drop role zecret_api;
	`.catch(() => {})
}
export const action = async (sql, { roles: { service, migration } }) => {
	await sql`
		set role ${sql.unsafe(migration)}
	`

	await sql`
		create extension citext schema public;
	`

	await sql`
		create schema zecret;
	`
	await sql`
		grant usage on schema zecret to ${sql.unsafe(service)};
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
		,like zecret.meta
	);`

	await sql`
		create table zecret.org(
				organization_name public.citext primary key
				,like zecret.meta
		);
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
				, like zecret.meta
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
			, like zecret.meta
		);
	`

	await sql`
		create table zecret.group_user(
			group_name public.citext not null
			, organization_name public.citext not null
			, user_id uuid references zecret.user(user_id)
			, primary key (group_name, user_id)
			, like zecret.meta
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
		insert into zecret.grant_level (grant_level) values ('read'), ('write'), ('grant');
	`

	await sql`
		create table zecret.grant(
			path public.citext not null
			, organization_name public.citext null
			, group_name public.citext null
			, user_id uuid null
			, grant_level public.citext not null
				references zecret.grant_level(grant_level)
			, like zecret.meta

			, primary key (organization_name, path, grant_level, group_name, user_id)
			, constraint either_user_or_group
				check (
						(group_name is null) <> (user_id is null)
				)
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
		create table zecret.secret(
			path public.citext not null
			, organization_name public.citext not null
				references zecret.org(organization_name)
				on update cascade
				on delete cascade
				deferrable initially deferred
			, key public.citext not null
			, value text not null
			, primary key (organization_name, path, key)
			, like zecret.meta
		);
	`

	await sql`
		create role zecret_api with login password 'zecret' noinherit;
	`

	await sql`
		grant ${sql.unsafe(service)} to zecret_api;
	`
}
