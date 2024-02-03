export const name = 'Org'

async function trigger(sql, name, occasion, events, options) {
	await sql`
		create function ${sql(name)}()
		returns trigger as $trigger_fn_body$
		begin
			${options.execute}
			;
			${
				options.execute.strings.some((x) => x.toLowerCase().match(/\breturn\b/))
					? sql.unsafe``
					: sql`return null;`
			}
			
		end;
		$trigger_fn_body$
		language plpgsql
		security definer
	`

	await sql`
		create trigger ${sql.unsafe(name.split('.')[1])} ${sql.unsafe(
		occasion
	)} ${sql.unsafe(events.join(' or '))}
		on ${sql(options.on)}
		for each ${sql.unsafe(options.forEach)}
		execute function ${sql(name)}()
	`
}

async function triggerMultiple(sql, _prefix, options) {
	const prefix = _prefix + '_'
	for (let occasion of ['after', 'before', 'instead of']) {
		if (!(occasion in options)) {
			continue
		}

		let events = options[occasion]

		for (let event of Object.keys(events)) {
			await trigger(sql, `${prefix}_${occasion}_${event}`, occasion, [event], {
				execute: events[event],
				...options
			})
		}
	}
}

export const action = async (sql, { roles }) => {
	await sql`
		create table zecret.org(
			org_id public.citext primary key,
			primary_owner public.citext references zecret.user(user_id)
				on update cascade
				on delete cascade
		)
	`

	await triggerMultiple(sql, 'zecret.auto_org', {
		on: 'zecret.user',
		forEach: 'row',
		after: {
			insert: sql`
				insert into zecret.org(org_id, primary_owner)
				values (NEW.user_id, NEW.user_id)
			`,
			update: sql`
				update zecret.org
				set org_id = NEW.user_id
				where org_id = OLD.user_id
			`,
			delete: sql`
				delete from zecret.org
				where org_id = OLD.user_id
			`
		}
	})

	await sql`
		grant select, insert, update, delete on zecret.org to ${sql(roles.service)}
	`

	await sql`
		alter table zecret.org
		enable row level security
	`

	await sql`
		create function zecret.is_superuser()
		returns boolean
		as $$
			select current_setting('zecret.superuser', true) = 'true'::text
		$$
		language sql
		set search_path = ''
		security invoker
		stable
	`
	await sql`
		create function zecret.get_user_id()
		returns public.citext
		as $$
			select current_setting('zecret.user_id', true)::public.citext
		$$
		language sql
		set search_path = ''
		security invoker
		stable
	`
	await sql`
		create function zecret.does_user_own_org(_org zecret.org, _user_id public.citext)
		returns boolean
		as $$
			select _org.primary_owner = _user_id
		$$
		language sql
		set search_path = ''
		security invoker
		stable
	`
	await sql`
		create function zecret.is_user_member_of_org(_org zecret.org, _user_id public.citext)
		returns boolean
		as $$
			-- todo-james implement groups
			select false
		$$
		language sql
		set search_path = ''
		security invoker
		stable
	`

	async function policy(config) {
		const prefix =
			config.name ?? `${config.for.join('_and_')}_to_${config.to ?? 'all'}_`
		for (let operation of config.for) {
			await sql`
				create policy ${sql.unsafe(`${prefix}_${operation}`)} on ${config.on}
				for ${sql.unsafe(operation)} 
				to ${sql(roles.service)}
				${config.using ? sql`using (${config.using})` : sql.unsafe``}
				${config.check ? sql`with check (${config.check})` : sql.unsafe``}
			`
		}
	}

	await policy({
		on: `zecret.org`,
		for: ['select', 'update'],
		to: roles.service,
		using: sql`
			zecret.does_user_own_org(org, zecret.get_user_id())
			or zecret.is_user_member_of_org(org, zecret.get_user_id())
			or zecret.is_superuser()
		`
	})

	await policy({
		on: `zecret.org`,
		for: ['insert'],
		to: roles.service,
		check: sql`
			true
		`
	})

	// for (let [policy_name, operation] of [
	// 	['read', 'select'],
	// 	['modify', 'update']
	// ]) {
	// 	await sql`
	// 		create policy ${sql.unsafe(policy_name)} on zecret.org
	// 		for ${sql.unsafe(operation)}
	// 		to ${sql(roles.service)}
	// 		using (
	// 			zecret.does_user_own_org(org, zecret.get_user_id())
	// 			or zecret.is_user_member_of_org(org, zecret.get_user_id())
	// 			or zecret.is_superuser()
	// 		)
	// 	`
	// }

	// await sql`
	// 	create policy add on zecret.org
	// 	for insert
	// 	to ${sql(roles.service)}
	// 	with check (true)
	// `

	await sql`
		grant ${sql(roles.service)} to ${sql(
		new URL(process.env.API_DATABASE_URL).username
	)}
	`
}
