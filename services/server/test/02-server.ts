import test from 'node:test'
import * as fs from 'node:fs/promises'
import { LoginCommand } from '../src/server-login.js'
import { InitializeStoreCommand } from '../src/server-initialize.js'

import { WhoAmICommand } from '../src/server-whoami.js'
import RefreshTokenCommand from '../src/server-token-refresh.js'
import ManageSecretsCommand from '../src/server-manage-secrets.js'
import RequestSecretsCommand from '../src/server-request-secrets.js'
import ManageOrganizationCommand from '../src/server-manage-organization.js'
import ListGroupCommand from '../src/server-list-groups.js'
import assert from 'node:assert'
import { state } from '../src/server-state'
import {
	decryptWithGithubPrivateKey,
	decryptWithSecret,
	encryptWithBufferPublicKey,
	encryptWithSecret,
	parseJwt
} from '../src/util.js'

const afters: (() => any)[] = []

test('server', async (t) => {
	const initializeStoreRes = await InitializeStoreCommand({
		tag: 'InitializeStoreCommand',
		value: {
			key_pair: {
				private_key: await fs.readFile(
					'/home/self/src/@/zecret/output/keypair/server',
					'utf-8'
				),
				public_key: await fs.readFile(
					'/home/self/src/@/zecret/output/keypair/server.pub',
					'utf-8'
				)
			},
			database_url: process.env.DATABASE_URL as string,
			token_secret: 'secret'
		}
	})
	let loginResponse = await LoginCommand({
		tag: 'LoginCommand',
		value: {
			gh: {
				public_key: await fs.readFile('/home/self/.ssh/id_rsa.pub', 'utf8'),
				username: 'JAForbes'
			}
		}
	})
	assert(loginResponse.tag === 'LoginResponseOk')
	assert(state.state === 'active')
	let jwt = await decryptWithGithubPrivateKey(
		loginResponse.value.encrypted_token,
		await fs.readFile('/home/self/.ssh/id_rsa', 'utf8')
	)
	let server_enc_jwt = await encryptWithBufferPublicKey(
		jwt,
		state.key_pairs[0].public_key
	)
	let whoAmIResponse = await WhoAmICommand({
		tag: 'WhoAmICommand',
		value: {
			token: server_enc_jwt
		}
	})
	let refreshResponse = await RefreshTokenCommand({
		tag: 'RefreshTokenCommand',
		value: {
			token: server_enc_jwt
		}
	})
	assert(refreshResponse.tag === 'RefreshTokenOk')
	let encodedJwt = decryptWithGithubPrivateKey(
		refreshResponse.value.token,
		await fs.readFile('/home/self/.ssh/id_rsa', 'utf8')
	)
	let parsedJwt = await parseJwt(encodedJwt, { autoRefresh: false })
	server_enc_jwt = await encryptWithBufferPublicKey(
		encodedJwt,
		state.key_pairs[0].public_key
	)
	let JAForbes_server_enc_jwt = server_enc_jwt
	let manageOrgResponse = await ManageOrganizationCommand({
		tag: 'ManageOrganizationCommand',
		value: {
			organization_name: 'harth',
			grants: {
				add: [
					{
						tag: 'GithubUserGrant',
						github_user_id: 'jbravoe',
						grant_level: 'write',
						path: '/home/jbravoe/'
					},
					{
						tag: 'GroupGrant',
						group_name: 'developers',
						grant_level: 'write',
						path: '/odin/'
					}
				],
				remove: [
					{
						tag: 'GroupGrant',
						group_name: 'developers',
						grant_level: 'read',
						path: '/dropoff/'
					},
					{
						tag: 'GroupGrant',
						group_name: 'developers',
						grant_level: 'write',
						path: '/dropoff/'
					}
				]
			},
			group_members: {
				add: [
					{
						tag: 'GroupGithubUser',
						github_user_id: 'jbravoe',
						group_name: 'developers'
					}
				],
				remove: []
			},
			users: { add: [], remove: [] },
			groups: { add: ['developers'], remove: ['admin'] },
			token: server_enc_jwt,
			admins: {
				add: [],
				remove: []
			}
		}
	})
	afters.push(async () => {
		await ManageOrganizationCommand({
			tag: 'ManageOrganizationCommand',
			value: {
				organization_name: 'harth',
				grants: {
					add: [],
					remove: [
						{
							tag: 'GithubUserGrant',
							github_user_id: 'jbravoe',
							grant_level: 'write',
							path: '/home/jbravoe/'
						},
						{
							tag: 'GroupGrant',
							group_name: 'developers',
							grant_level: 'write',
							path: '/odin/'
						},
						{
							tag: 'GroupGrant',
							group_name: 'developers',
							grant_level: 'read',
							path: '/dropoff/'
						},
						{
							tag: 'GroupGrant',
							group_name: 'developers',
							grant_level: 'write',
							path: '/dropoff/'
						}
					]
				},
				group_members: {
					add: [],
					remove: [
						{
							tag: 'GroupGithubUser',
							github_user_id: 'jbravoe',
							group_name: 'developers'
						}
					]
				},
				users: { add: [], remove: [] },
				groups: { add: [], remove: ['admin', 'developers'] },
				token: server_enc_jwt,
				admins: {
					add: [],
					remove: []
				}
			}
		})
	})
	assert(manageOrgResponse.tag === 'ManageOrganizationOk')
	let manageSecretsResponse = await ManageSecretsCommand({
		tag: 'ManageSecretsCommand',
		value: {
			token: server_enc_jwt,
			remove: [],
			add: [
				{
					organization_name: 'harth',
					key: 'DATABASE_URL',
					value: encryptWithSecret(
						'postgres://api:password@odin.db:5432/database',
						parsedJwt.shared_secret
					),
					path: '/odin/api'
				},
				{
					organization_name: 'harth',
					key: 'DATABASE_URL',
					value: encryptWithSecret(
						'postgres://sql:password@odin.db:5432/database',
						parsedJwt.shared_secret
					),
					path: '/odin/sql'
				},
				{
					organization_name: 'harth',
					key: 'DATABASE_URL',
					value: encryptWithSecret(
						'postgres://auth:password@odin.db:5432/database',
						parsedJwt.shared_secret
					),
					path: '/odin/auth'
				},
				{
					organization_name: 'harth',
					key: 'DATABASE_URL',
					value: encryptWithSecret(
						'postgres://api:password@dropoff.db:5432/database',
						parsedJwt.shared_secret
					),
					path: '/dropoff/api'
				}
			]
		}
	})
	assert.equal(manageSecretsResponse.tag, 'ManageSecretsOk')
	let cliRequestSecretsResponse = await RequestSecretsCommand({
		tag: 'RequestSecretsCommand',
		value: {
			organization_name: 'harth',
			paths: ['/odin'],
			token: server_enc_jwt
		}
	})
	assert(cliRequestSecretsResponse.tag === 'RequestSecretsOk')
	assert.notEqual(cliRequestSecretsResponse.value.secrets.length, 0)
	assert.equal(
		'postgres://api:password@odin.db:5432/database',
		decryptWithSecret(
			cliRequestSecretsResponse.value.secrets.find(
				(x) => x.path === '/odin/api' && x.key == 'DATABASE_URL'
			)!.value,
			parsedJwt.shared_secret
		)
	)
	loginResponse = await LoginCommand({
		tag: 'LoginCommand',
		value: {
			gh: {
				username: 'JBravoe',
				public_key: await fs.readFile('/home/self/.ssh/jbravoe.pub', 'utf8')
			}
		}
	})
	assert(loginResponse.tag === 'LoginResponseOk')
	jwt = await decryptWithGithubPrivateKey(
		loginResponse.value.encrypted_token,
		await fs.readFile('/home/self/.ssh/jbravoe', 'utf8')
	)
	parsedJwt = await parseJwt(jwt, { autoRefresh: false })
	server_enc_jwt = await encryptWithBufferPublicKey(
		jwt,
		state.key_pairs[0].public_key
	)
	let JBravoe_server_enc_jwt = server_enc_jwt
	whoAmIResponse = await WhoAmICommand({
		tag: 'WhoAmICommand',
		value: {
			token: server_enc_jwt
		}
	})
	assert(whoAmIResponse.tag === 'WhoAmIOk')
	assert(whoAmIResponse.value.gh.username === 'jbravoe')
	cliRequestSecretsResponse = await RequestSecretsCommand({
		tag: 'RequestSecretsCommand',
		value: {
			organization_name: 'harth',
			paths: ['/odin'],
			token: server_enc_jwt
		}
	})
	assert(cliRequestSecretsResponse.tag === 'RequestSecretsOk')
	assert(
		cliRequestSecretsResponse.value.secrets.length > 0 &&
			cliRequestSecretsResponse.value.secrets.every((x) =>
				x.path.startsWith('/odin/')
			)
	)
	manageOrgResponse = await ManageOrganizationCommand({
		tag: 'ManageOrganizationCommand',
		value: {
			organization_name: 'harth',
			grants: {
				add: [],
				remove: []
			},
			group_members: {
				add: [],
				remove: []
			},
			users: { add: [], remove: [] },
			groups: { add: ['developers'], remove: [] },
			token: JBravoe_server_enc_jwt,
			admins: {
				add: [],
				remove: []
			}
		}
	})
	assert(manageOrgResponse.tag === 'ManageOrganizationErr')
	assert(manageOrgResponse.value.message === 'Insufficient Permissions')
	let listGroupResponse = await ListGroupCommand({
		tag: 'ListGroupCommand',
		value: {
			organization_name: 'harth',
			token: JAForbes_server_enc_jwt
		}
	})
	assert(listGroupResponse.tag === 'ListGroupOk')
	assert(
		listGroupResponse.value.groups.find((x) => x.group_name === 'developers')
	)
	assert(
		listGroupResponse.value.groups.find((x) => x.group_name === 'developers')
			?.users.length ?? 0 >= 2
	)
	listGroupResponse = await ListGroupCommand({
		tag: 'ListGroupCommand',
		value: {
			organization_name: 'harth',
			token: JBravoe_server_enc_jwt
		}
	})
	assert(listGroupResponse.tag === 'ListGroupOk')
	assert(
		listGroupResponse.value.groups.find((x) => x.group_name === 'developers')
	)
	assert(
		listGroupResponse.value.groups.find((x) => x.group_name === 'developers')
			?.users.length ?? 0 >= 2
	)
	cliRequestSecretsResponse = await RequestSecretsCommand({
		tag: 'RequestSecretsCommand',
		value: {
			organization_name: 'harth',
			paths: ['/'],
			token: JBravoe_server_enc_jwt
		}
	})
	assert(cliRequestSecretsResponse.tag === 'RequestSecretsOk')
	assert(
		cliRequestSecretsResponse.value.secrets.length > 0 &&
			cliRequestSecretsResponse.value.secrets.every((x) =>
				x.path.startsWith('/odin/')
			)
	)
	manageOrgResponse = await ManageOrganizationCommand({
		tag: 'ManageOrganizationCommand',
		value: {
			organization_name: 'harth',
			grants: {
				add: [
					{
						tag: 'GroupGrant',
						group_name: 'developers',
						grant_level: 'read',
						path: '/dropoff/'
					}
				],
				remove: []
			},
			group_members: { add: [], remove: [] },
			users: { add: [], remove: [] },
			groups: { add: [], remove: [] },
			token: JAForbes_server_enc_jwt,
			admins: {
				add: [],
				remove: []
			}
		}
	})
	assert(manageOrgResponse.tag === 'ManageOrganizationOk')
	cliRequestSecretsResponse = await RequestSecretsCommand({
		tag: 'RequestSecretsCommand',
		value: {
			organization_name: 'harth',
			paths: ['/'],
			token: JBravoe_server_enc_jwt
		}
	})
	assert(cliRequestSecretsResponse.tag === 'RequestSecretsOk')
	assert(
		cliRequestSecretsResponse.value.secrets.length > 0 &&
			cliRequestSecretsResponse.value.secrets.every(
				(x) => x.path.startsWith('/odin/') || x.path.startsWith('/dropoff/')
			)
	)
	manageSecretsResponse = await ManageSecretsCommand({
		tag: 'ManageSecretsCommand',
		value: {
			token: JBravoe_server_enc_jwt,
			remove: [],
			add: [
				{
					organization_name: 'harth',
					key: 'DATABASE_URL',
					value: encryptWithSecret(
						'postgres://api:password@odin.db:5433/database',
						parsedJwt.shared_secret
					),
					path: '/odin/api'
				}
			]
		}
	})
	assert(manageSecretsResponse.tag === 'ManageSecretsOk')
	manageSecretsResponse = await ManageSecretsCommand({
		tag: 'ManageSecretsCommand',
		value: {
			token: JBravoe_server_enc_jwt,
			remove: [],
			add: [
				{
					organization_name: 'harth',
					key: 'DATABASE_URL',
					value: encryptWithSecret(
						'postgres://api:password@dropoff.db:5433/database',
						parsedJwt.shared_secret
					),
					path: '/dropoff/api'
				}
			]
		}
	})
	assert(
		manageSecretsResponse.tag === 'ManageSecretsErr',
		'Cannot upsert with read access'
	)
	manageSecretsResponse = await ManageSecretsCommand({
		tag: 'ManageSecretsCommand',
		value: {
			token: JBravoe_server_enc_jwt,
			remove: [],
			add: [
				{
					organization_name: 'harth',
					key: 'DATABASE_URL',
					value: encryptWithSecret(
						'postgres://api:password@evgen.db:5432/database',
						parsedJwt.shared_secret
					),
					path: '/evgen/api'
				}
			]
		}
	})
	assert(
		manageSecretsResponse.tag === 'ManageSecretsErr',
		'Cannot upsert with no access'
	)
	manageOrgResponse = await ManageOrganizationCommand({
		tag: 'ManageOrganizationCommand',
		value: {
			organization_name: 'harth',
			grants: {
				add: [
					{
						tag: 'GroupGrant',
						group_name: 'developers',
						grant_level: 'write',
						path: '/dropoff/'
					}
				],
				remove: [
					{
						tag: 'GroupGrant',
						group_name: 'developers',
						grant_level: 'read',
						path: '/dropoff/'
					}
				]
			},
			group_members: { add: [], remove: [] },
			users: { add: [], remove: [] },
			groups: { add: [], remove: [] },
			token: JAForbes_server_enc_jwt,
			admins: {
				add: [],
				remove: []
			}
		}
	})
	manageSecretsResponse = await ManageSecretsCommand({
		tag: 'ManageSecretsCommand',
		value: {
			token: JBravoe_server_enc_jwt,
			remove: [],
			add: [
				{
					organization_name: 'harth',
					key: 'DATABASE_URL',
					value: encryptWithSecret(
						'postgres://api:password@dropoff.db:5433/database',
						parsedJwt.shared_secret
					),
					path: '/dropoff/api'
				}
			]
		}
	})
	assert(manageSecretsResponse.tag === 'ManageSecretsOk')
	manageSecretsResponse = await ManageSecretsCommand({
		tag: 'ManageSecretsCommand',
		value: {
			token: JBravoe_server_enc_jwt,
			add: [],
			remove: [
				{
					organization_name: 'harth',
					key: 'DATABASE_URL',
					path: '/dropoff/api'
				}
			]
		}
	})
	assert(manageSecretsResponse.tag === 'ManageSecretsOk')
})

test.after(async () => {
	for (let fn of afters) {
		await fn()
	}
	if (state.state == 'active') {
		await state.postgres.end()
	}
})
