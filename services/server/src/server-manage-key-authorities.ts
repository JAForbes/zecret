export type User = {
	user_id: string
	user_name: string
}

export type ManageKeyAuthoritiesCommand = {
	tag: 'ManageKeyAuthoritiesCommand'
	value: {
		templates: {
			patch: {
				[name: string]: {
					server: (user: User) => URL
					priority: number
				}
			}
			remove: string[]
		}
		keys: {
			public_key: string
		}
	}
}
