import testUserRls from "./test/user-rls.js"
import testOrgRls from "./test/org-and-group-rls.js"

export const name = "RLS Policies"

export const action = async (sql, { roles }) => {
	const service = sql.unsafe(roles.service)

	await sql`
		create or replace function zecret.set_active_user(_user_id uuid)
		returns void
		as $$
			select set_config('zecret.user_id', _user_id::text, true);
		$$
		language sql
		set search_path = ''
		security definer
		;
	`

	await sql`
		create or replace function zecret.set_active_org(_org public.citext)
		returns void
		as $$
			select set_config('zecret.org', _org::text, true);
		$$
		language sql
		set search_path = ''
		security definer
		;
	`

	await sql`
		grant execute on function zecret.set_active_user to ${service};
	`

	await sql`
		grant execute on function zecret.set_active_org to ${service};
	`

	await sql`
		create policy api_select_user on zecret.user
		for select
		to ${service}
		using ( deleted_at is null )
	;
	`
	await sql`
		create policy api_update_user on zecret.user
		for update
		to ${service}
		using ( user_id = zecret.get_active_user() )
	;
	`
	await sql`
		create policy api_insert_user on zecret.user
		for insert
		to ${service}
		with check ( true )
	;
	`

	await sql`
		create or replace function zecret.user_is_in_org(_organization_name public.citext, _user_id uuid)
		returns boolean
		as $$
			select exists (
				select true
				from zecret.org_user OU
				where (OU.user_id, OU.organization_name) = (_user_id, _organization_name)
			)
			or exists (
				select true
				from zecret.org O
				where (O.organization_name, O.primary_owner_id) = (_organization_name, _user_id)
			)
		$$
		language sql
		set search_path = ''
		security definer
		;
	`

	await sql`
		grant execute on function zecret.user_is_in_org to ${service};
	`

	await sql`
		create policy api_select_org_user on zecret.org_user
		for select
		to ${service}
		using (
			deleted_at is null
			and zecret.user_is_in_org( organization_name, zecret.get_active_user() )
		)
		;
	`

	await sql`
		create policy api_select_org on zecret.org
		for select
		to ${service}
		using (
			deleted_at is null
			and (
				zecret.user_is_in_org( organization_name, zecret.get_active_user() )

				-- row may not exist yet, so fn fails for initial create
				or primary_owner_id = zecret.get_active_user()
			)
		)
		;
	`

	await sql`
		create policy api_insert_org on zecret.org
		for insert
		to ${service}
		with check (
			zecret.get_active_user() is not null
		)
	`

	await sql`
		create or replace function zecret.has_root_grant(_organization_name public.citext, _user_id uuid)
		returns boolean
		as $$
			select exists
			-- is admin
			(
				select primary_owner_id
				from zecret.org O
				where
					O.organization_name = _organization_name
					and O.primary_owner_id = _user_id
			)
			or -- user has / grant permission
			exists (
				select G.user_id
				from zecret.grant_user G
				where G.path = '/'
				and (G.organization_name, G.user_id) = (_organization_name, _user_id)
				and G.grant_level = 'grant'
			)
			or -- user has / grant permission via a group
			exists (
				select GU.user_id
				from zecret.grant_group GT
				inner join zecret.group_user GU on
					(GT.organization_name, GT.group_name, _user_id) = (GU.organization_name, GU.group_name, GU.user_id)
				where GT.path = '/'
				and GT.organization_name = _organization_name
				and GT.grant_level = 'grant'
			)

		$$
		language sql
		set search_path = ''
		security definer
		;
	`

	await sql`grant execute on function zecret.has_root_grant to ${service}`

	await sql`
		create policy api_update_org on zecret.org
		for update
		to ${service}
		using (
			zecret.has_root_grant(organization_name, zecret.get_active_user())
		)
	`

	await sql`
		create policy api_insert_org_user on zecret.org_user
		for insert
		to ${service}
		with check (
			zecret.has_root_grant( organization_name, zecret.get_active_user() )
		)
	`

	await sql`
		create policy api_insert_group on zecret.group
		for insert
		to ${service}
		with check (
			zecret.has_root_grant( organization_name, zecret.get_active_user() )
		)
	`

	await sql`
		create policy api_insert_group_user on zecret.group_user
		for insert
		to ${service}
		with check (
			zecret.has_root_grant( organization_name, zecret.get_active_user() )
			and zecret.user_is_in_org( organization_name, user_id )
		)
	`

	await sql`
		create or replace function zecret.has_write_permission_at_path(
			_organization_name public.citext
			, _user_id uuid
			, _path public.citext
		)
		returns boolean
		as $$
			select
			-- is admin
			exists
			(
				select primary_owner_id
				from zecret.org O
				where
					O.organization_name = _organization_name
					and O.primary_owner_id = _user_id
				limit 1
			)
			or -- user has / grant permission
			exists (
				select G.user_id
				from zecret.grant_user G
				where _path like G.path||'%'
				and (G.organization_name, G.user_id) = (_organization_name, _user_id)
				and G.grant_level in ('grant', 'write')
				limit 1
			)
			or -- user has / grant permission via a group
			exists (
				select GU.user_id
				from zecret.grant_group GT
				inner join zecret.group_user GU on
					(GT.organization_name, GT.group_name, _user_id) = (GU.organization_name, GU.group_name, GU.user_id)
				where _path like GT.path||'%'
				and GT.organization_name = _organization_name
				and GT.grant_level in ('grant', 'write')
				limit 1
			)

		$$
		language sql
		set search_path = ''
		security definer
		;
	`

	await sql`
		create or replace function zecret.has_grant_permission_at_path(
			_organization_name public.citext
			, _user_id uuid
			, _path public.citext
		)
		returns boolean
		as $$
			select exists
			-- is admin
			(
				select primary_owner_id
				from zecret.org O
				where
					O.organization_name = _organization_name
					and O.primary_owner_id = _user_id
				limit 1
			)
			or -- user has / grant permission
			exists (
				select G.user_id
				from zecret.grant_user G
				where _path like G.path||'%'
				and (G.organization_name, G.user_id) = (_organization_name, _user_id)
				and G.grant_level in ('grant')
				limit 1
			)
			or -- user has / grant permission via a group
			exists (
				select GU.user_id
				from zecret.grant_group GT
				inner join zecret.group_user GU on
					(GT.organization_name, GT.group_name, _user_id) = (GU.organization_name, GU.group_name, GU.user_id)
				where _path like GT.path||'%'
				and GT.organization_name = _organization_name
				and GT.grant_level in ('grant')
				limit 1
			)

		$$
		language sql
		set search_path = ''
		security definer
		;
	`

	await sql`
		create or replace function zecret.has_read_permission_at_path(
			_organization_name public.citext
			, _user_id uuid
			, _path public.citext
		)
		returns boolean
		as $$
			select exists
			-- is admin
			(
				select primary_owner_id
				from zecret.org O
				where
					O.organization_name = _organization_name
					and O.primary_owner_id = _user_id
				limit 1
			)
			or -- user has / read permission
			exists (
				select G.user_id
				from zecret.grant_user G
				where _path like G.path||'%'
				and (G.organization_name, G.user_id) = (_organization_name, _user_id)
				limit 1
			)
			or -- user has / read permission via a group
			exists (
				select GU.user_id
				from zecret.grant_group GT
				inner join zecret.group_user GU on
					(GT.organization_name, GT.group_name, _user_id) = (GU.organization_name, GU.group_name, GU.user_id)
				where _path like GT.path||'%'
				and GT.organization_name = _organization_name
				limit 1
			)

		$$
		language sql
		set search_path = ''
		security definer
		;
	`

	await sql`
		create policy api_insert_secret on zecret.secret
		for insert
		to ${service}
		with check (
			
			zecret.has_write_permission_at_path(
				organization_name
				, zecret.get_active_user()
				, path
			)
		)
	`

	await sql`
		create policy api_update_secret on zecret.secret
		for update
		to ${service}
		using (
			zecret.has_write_permission_at_path(
				organization_name
				, zecret.get_active_user()
				, path
			)
		)
	`

	await sql`
		create policy api_insert_grant_user on zecret.grant_user
		for insert
		to ${service}
		with check (
			zecret.has_grant_permission_at_path(
				organization_name
				, zecret.get_active_user()
				, path
			)
		)
	`

	await sql`
		create policy api_insert_grant_user on zecret.grant_group
		for insert
		to ${service}
		with check (
			zecret.has_grant_permission_at_path(
				organization_name
				, zecret.get_active_user()
				, path
			)
		)
	`

	await sql`
		create policy api_select_secret on zecret.secret
		for select
		to ${service}
		using (
			zecret.has_read_permission_at_path(
				organization_name
				, zecret.get_active_user()
				, path
			)
		)
	`

	await sql`
		create policy api_select_server_public_key on zecret.server_public_key
		for select
		to ${service}
		using (true)
	`

	await sql`
		create policy api_insert_server_public_key on zecret.server_public_key
		for insert
		to ${service}
		with check (true)
	`

	await sql`
		grant ${service} to zecret_api
	`

	await testUserRls(sql)
	// await testOrgRls(sql)
}
