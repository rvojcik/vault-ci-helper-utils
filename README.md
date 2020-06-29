# vault-ci-helper-utils

Useful utilities to help working with Vault in CI/CD environment

Primary used in containers and CI/CD pipelines to help communicate with HashiCorp Vault
secret server.

## vault-get-secret-data.sh

Bash script used for

* auth against vault using token or AppRole auth
* get secret from KV (version 1 or version 2)

You can use this script to just AppRole auth and use retrieved token as you wish.

Script print some information to STDERR instead of STDOUT, so you can use pipes and shell kungfu as you wish.

### Key value storage v1 vs v2

You don't have to deal with that, the script figure out it for you. It tries always v1 and if it's fails to get it tries v2.
You can set secret base with data in patch to avoid that behaviour but you don't have to.

### Authentification (Approle or Token)

Script using approle auth, you have to set ENV variables to pass auth information to it.
  - VAULT_ADDR, address of the vault server
  - VAULT_ROLE_ID
  - VAULT_SECRET_ID

Alternatively you can set `VAULT_TOKEN` to use token based autentification.

Then you can call script with all options to get secrets, it auth automatically.
However you can use just auth mechanism of it to retrieve auth token and use it on your own.

```
# Login
cat $(vault-get-secret-data.sh login)

# Logout
vault-get-secret-data.sh logout
```

You don't have to do login in separete step. But you can take advantage of this to use this script only for AppRole Auth to retrieve auth token.

### Get Secrets

Simple way just get me secrets from kv storage at `/deploy` and secret path `/mysecret`, so full path is `/deploy/mysecret`.


```
# Secrets to stdout
vault-get-secret-data.sh -b /deploy -p /mysecret

# Secrets to file
vault-get-secret-data.sh -b /deploy -p /mysecret -o ./my-secrets.file

# Put specific secrets value to file
#
# We have secret called kubernetes with key jsonfile which contains json auth information
vault-get-secret-data.sh -b /deploy -p /kubernetes -s jsonfile -o ./kubernetes.json
```

Complex way, I have more environments (folders) and i want to deploy correct secret for correct environment.
For example you can have production and dev environment in you CI/CD pipeline, and different secrets for them in Vault.

```
# For example we have secrets with this specific setup /deploy/tech/<environment>/kubernetes/secret
# It can be whatever you want

vault-get-secret-data.sh -b /deploy -p /tech/production/kubernetes/secret -e production

# If you have your environment in some CI variable, you can use CI_* in -e option
vault-get-secret-data.sh -b /deploy -p /tech/production/kubernetes/secret -e CI_ENVIRONMENT_SLUG

```
To be clear, `-b` is not strictly the path of the storage engine, it is just base path which tells script where to find environments if you want to use them.

## Output Formats

You can use `-f` to specify output format, we support shell, json and YAML

Output examples

```
# Shell
my_secret_key="my secret value"

# JSON
{
  "my_secret_key": "my secret value"
}

# YAML
---
my_secret_key: "my secret value"
```

For more information use help of the script

