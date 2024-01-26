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
	await sql`
		create table zecret.user(
			user_name public.citext primary key
			,email public.citext not null
			,avatar_url public.citext not null

			-- normally we'll use their username as just an internal id
			-- not a display name, we use their key authority username
			-- but if they explicitly edit it, we render that primarily instead
			,user_name_edited boolean not null default false
			,like zecret.meta including defaults
		);
	`

	await sql`
		create or replace function zecret.get_active_user()
		returns public.citext
		as $$
			with xs as (
				select current_setting('zecret.user_name', true) as v
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
		create table zecret.org(
				organization_name public.citext primary key
				,primary_owner_id public.citext not null 
					references zecret.user(user_name) 
						on delete cascade
							deferrable initially deferred
					default zecret.get_active_user()
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
		-- known servers that can associate a key pair with a user identity
		-- these servers can be used by any organization
		create table zecret.known_key_authority(
			-- e.g. github / gitlab
			key_authority_name public.citext primary key

			-- a mustache template that resolves to a key url path
			-- the template has access to the user and org record fields
			, url_template public.citext

			-- e.g. https://github.com / https://gitlab.com
			, origin public.citext

			, like zecret.meta including defaults
		);
	`

	await sql`
		insert into zecret.known_key_authority(
			key_authority_name, url_template, origin
		)
		values 
			('github', '{{user_name}}.keys', 'https://github.com')
			, ('gitlab', '{{user_name}}.keys', 'https://gitlab.com')
			, ('zecret', '/api/keys/{{user_name}}.keys', 'https://zecret.fly.dev')
	`

	await sql`
		-- custom servers that can associate a key pair with a user identity
		-- these may be internal keyservers on an intranet, or just vendors
		-- we haven't explicitly supported
		create table zecret.org_key_authority(
			key_authority_name public.citext unique

			-- a mustache template that resolves to a key url path
			-- the template has access to the user and org record fields
			, url_template public.citext

			-- e.g. http://localhost:3000 / https://id.internal.company.com
			, origin public.citext
			
			, organization_name public.citext references zecret.org(organization_name)
			
			, like zecret.meta including defaults
			, primary key (organization_name, key_authority_name)
		);
	`

	await sql`
		-- From the perspective of the schema, an organization opts in to the known key authorities
		-- but in reality we automatically prefill the table on org creation to include github + gitlab
		-- if an organization wants to opt out, we delete one of these records
		create table zecret.known_key_authority_enabled(
			key_authority_name public.citext references zecret.known_key_authority(key_authority_name)
			, organization_name public.citext references zecret.org(organization_name)

			, like zecret.meta including defaults
			, primary key (key_authority_name, organization_name)
		);
	`

	await sql`
		-- associate a user's username with a known key authority
		create table zecret.known_key_authority_user_name(
			user_name public.citext references zecret.user(user_name)
				on delete cascade
				on update cascade
			, key_authority_user_name public.citext
			, key_authority_name public.citext references zecret.known_key_authority(key_authority_name)
				on delete cascade
				on update cascade

			, like zecret.meta including defaults
			, primary key (key_authority_name, user_name)
		)
	`

	await sql`
		-- associate a user's username with an org's custom key server
		create table zecret.org_key_authority_user_name(
			user_name public.citext references zecret.user(user_name)
				on delete cascade
				on update cascade
			, organization_name public.citext references zecret.org(organization_name)
				on delete cascade
				on update cascade
			, key_authority_user_name public.citext
			, key_authority_name public.citext

			, constraint fk_org_key_authority 
				foreign key (organization_name, key_authority_name) 
				references zecret.org_key_authority(organization_name, key_authority_name)
					on delete cascade
					on update cascade
			
			, primary key (organization_name, key_authority_name, user_name)
			, like zecret.meta including defaults
		)
	`

	await sql`
		-- public key associated with user for zecrets internal key server
		create table zecret.user_public_key(
			user_name public.citext references zecret.user(user_name)
			, public_key text
			, comment text not null

			, like zecret.meta including defaults
			, primary key (user_name, public_key, comment)
		)
	`

	await sql`
		create table zecret.group(
				group_name public.citext not null
				,organization_name public.citext
					not null
					references zecret.org(organization_name)
						on delete cascade
						on update cascade
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
			,user_name public.citext not null
				references zecret.user(user_name)
				on update cascade
				on delete cascade
				deferrable initially deferred
			, primary key (organization_name, user_name)
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
			,user_name public.citext not null
				references zecret.user(user_name)
				on update cascade
				on delete cascade
				deferrable initially deferred
			, primary key (organization_name, user_name)
			, like zecret.meta including defaults
		)
	`

	await sql`
		create table zecret.group_user(
			group_name public.citext not null
			, organization_name public.citext not null
			, user_name public.citext references zecret.user(user_name)
					on delete cascade
					deferrable initially deferred
			, primary key (group_name, user_name)
			, like zecret.meta including defaults
			, constraint fk_org_and_group foreign key(organization_name, group_name)
				references zecret.group(organization_name, group_name)
					on update cascade
					on delete cascade
					deferrable initially deferred
			, constraint fk_org_and_user foreign key(organization_name, user_name)
				references zecret.org_user(organization_name, user_name)
					on update cascade
					on delete cascade
					deferrable initially deferred
		);
	`

	await sql`
		create table zecret.group_known_key_authority_user(
			group_name public.citext not null
			, organization_name public.citext not null

			-- this has no reference to another table
			-- because you can grant access before a user exists
			, key_authority_user_name public.citext

			, key_authority_name public.citext 
				references zecret.known_key_authority (key_authority_name)
				on update cascade
				on delete cascade

			, constraint fk_org_and_group foreign key (organization_name, group_name)
				references zecret.group (organization_name, group_name)
					on update cascade
					on delete cascade
		);
	`

	await sql`
		create table zecret.group_org_key_authority_user(
			group_name public.citext not null
			, organization_name public.citext not null

			-- this has no reference to another table
			-- because you can grant access before a user exists
			, key_authority_user_name public.citext

			, key_authority_name public.citext 
				
			, constraint fk_org_key_authority foreign key (organization_name, key_authority_name)
				references zecret.org_key_authority (organization_name, key_authority_name)
					on update cascade
					on delete cascade

			, constraint fk_org_and_group foreign key (organization_name, group_name)
				references zecret.group (organization_name, group_name)
					on update cascade
					on delete cascade
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
		-- this is just used to store grants before a user signs up
		-- if a user already exists for that key authority, we just convert
		-- the request to a normal user grant, so the policies do not need
		-- to reference these grants, they are kind of like invites
		create table zecret.grant_known_key_authority_user(
			path public.citext not null
			, organization_name public.citext not null
			, key_authority_user_name public.citext not null
			, key_authority_name public.citext 
				references zecret.known_key_authority(key_authority_name)
					on delete cascade
					on update cascade
					deferrable initially deferred
			, grant_level public.citext not null
				references zecret.grant_level(grant_level)
					on update cascade
					on delete cascade
					deferrable initially deferred
			, like zecret.meta including defaults
			, primary key (
				organization_name
				, path
				, grant_level
				, key_authority_name
				, key_authority_user_name
			)
		)
	`
	await sql`
		-- this is just used to store grants before a user signs up
		-- if a user already exists for that key authority, we just convert
		-- the request to a normal user grant, so the policies do not need
		-- to reference these grants, they are kind of like invites
		create table zecret.grant_org_key_authority_user(
			path public.citext not null
			, organization_name public.citext not null
			, key_authority_user_name public.citext not null
			, key_authority_name public.citext 
			, grant_level public.citext not null
				references zecret.grant_level(grant_level)
					on update cascade
					on delete cascade
					deferrable initially deferred
			, like zecret.meta including defaults
			
			, primary key (
				organization_name
				, path
				, grant_level
				, key_authority_name
				, key_authority_user_name
			)

			, constraint fk_org_key_authority 
				foreign key (organization_name, key_authority_name) 
				references zecret.org_key_authority(organization_name, key_authority_name)
		)
	`

	await sql`
		create table zecret.grant_user(
			path public.citext not null
			-- why are these nullable?
			, organization_name public.citext null
			, user_name public.citext null
			, grant_level public.citext not null
				references zecret.grant_level(grant_level)
					on delete cascade
					deferrable initially deferred
			, like zecret.meta including defaults

			, primary key (organization_name, path, grant_level, user_name)

			, constraint fk_org_and_user foreign key(organization_name, user_name)
				references zecret.org_user(organization_name, user_name)
					on delete cascade
					on update cascade
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
					on delete cascade
					deferrable initially deferred
			, like zecret.meta including defaults

			, primary key (organization_name, path, grant_level, group_name)

			, constraint fk_org_and_group foreign key(organization_name, group_name)
				references zecret.group(organization_name, group_name)
					on delete cascade
					on update cascade
						deferrable initially deferred
		);
	`

	await sql`
		create view zecret.grant as
			select organization_name, path, null::public.citext as user_name, group_name, grant_level, created_at, updated_at, deleted_at
			from zecret.grant_group
			union all
			select organization_name, path, user_name, null::public.citext as group_name, grant_level, created_at, updated_at, deleted_at
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
					on delete cascade
					on update cascade
						deferrable initially deferred
			, key public.citext not null
			, value text not null
			, iv text not null
			, symmetric_secret text not null
			, server_public_key_id text not null 
					references zecret.server_public_key(server_public_key_id)
						on delete cascade
							deferrable initially deferred
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
		['zecret.secret', 'select, insert, update, delete'],
		['zecret.server_public_key', 'select, insert, update'],
		['zecret.known_key_authority', 'select'],
		['zecret.org_key_authority', 'select, insert, update, delete'],
		['zecret.known_key_authority_enabled', 'select, insert, update, delete'],
		['zecret.known_key_authority_user_name', 'select, insert, update, delete'],
		['zecret.org_key_authority_user_name', 'select, insert, update, delete'],
		['zecret.user_public_key', 'select, insert, update, delete'],
		['zecret.group_known_key_authority_user', 'select, insert, update, delete'],
		['zecret.group_org_key_authority_user', 'select, insert, update, delete'],
		['zecret.grant_known_key_authority_user', 'select, insert, update, delete'],
		['zecret.grant_org_key_authority_user', 'select, insert, update, delete']
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
