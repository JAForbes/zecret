# zecret server

## Org and Group Membership

You can grant access to a path to a user, or add a user to a group before they've even got a `zecret` account.

You do this by granting access via a key authority, the most common one is Github.

If you open your browser and go to `https://github.com/JAForbes.keys` you will see all the public keys on github listed for James Forbes' account. You can substitute `JAForbes` for any github username and you will see a list of their public keys.

We use these pages as a way to associate a user with a key pair. So if a user connects to zecret without an account but they use a keypair that is listed on their github we can automatically link that user to any previous grants.

We will automatically enroll that user into the organization, the relevant groups and the relevant user grants.

Because a user can have multiple key authorities we only use key authorities for grants if the user doesn't yet have an account. The moment they do, we will internally create the grant directly to the user so if they use another keypair that is associated with a key authority that you didn't grant, they'll still be able to access secrets/paths that you granted to them.

## Key Authorities

Zecret comes with support out of the box for gitlab and github, these are called known key authorities and are preconfigured. But you can also configure your own key authorities. These may be other vendors, or they may be servers you host within your own infrastructure that list public keys in the same format as github/gitlab given a particular username.

Username's are key authority specific, so you may use e.g. an employee's id at your company key server, a github username for github and so on.

Configuring a key server gives you complete control over which servers you trust. You can also disable the built in known key authorities for your organization.

## Built in Key Authority (Advanced)

Zecret server can also act as a key server. You can upload public keys to `zecret` via the CLI and Management UI and these will be listed at `$BASE_URL/api/keys/$USER_NAME`.

This feature is targeted at enterprise users who want complete control of which keys are issued and trusted.

When you start `zecret` server, you can also point the server at a directory of public keys and it will host those keys for you. However it will not automatically associate a key with a zecret user, it will simply host them at `$BASE_URL/api/keys/$dirname`. If the dirname matches the zecret username, the UI will suggest automatically linking these identities, but we keep this as an extra step to avoid potential breaches.

E.g. if you uploaded `JAForbes/home.pub` and `JAForbes/office.pub` and the base url was `yourdomain.com`, you would see the public key listed at `https://yourdomain.com/api/keys/JAForbes`.

This allows you to issue your own keys to users, distribute the keypairs to the development team to access their secrets, and then grant access to paths/groups using the filename of the key. To keep things simple, it is recommended to name the public keys that zecret hosted after the username of the user who is given the private keys.

For this example you could issue a grant to a zecret hosted public key via the CLI like so:

```bash
zecret grant read '/apps/*/development' zecret:JAForbes
```

Anyone who holds the private key for any public key listed at `https://yourdomain.com/api/keys/JAForbes` will be able to read secrets at that path.
