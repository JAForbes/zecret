import assert from 'node:assert'
import * as fs from 'node:fs/promises'

import {
	decryptWithGithubPrivateKey,
	decryptWithSecret,
	encryptWithBufferPublicKey,
	encryptWithSecret,
	parseJwt
} from './util.js'
import { LoginCommand } from './server-login.js'
import { InitializeStoreCommand } from './server-initialize.js'
import { state } from './server-state.js'
import { WhoAmICommand } from './server-whoami.js'
import RefreshTokenCommand from './server-token-refresh.js'
import ManageSecretsCommand from './server-manage-secrets.js'
import RequestSecretsCommand from './server-request-secrets.js'
import ManageOrganizationCommand from './server-manage-organization.js'
import ListGroupCommand from './server-list-groups.js'

export default async function server(argv: any & { _: string[] }) {}
