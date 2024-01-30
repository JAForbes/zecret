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

export const action = async (sql) => {
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
}
