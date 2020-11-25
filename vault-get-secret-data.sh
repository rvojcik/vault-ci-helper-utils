#!/bin/bash
#
# HELP_DESCRIPTION
#
# Vault Helper script for retrieving Secrets from Vault
# This Script cover some often used principles and basics.
# This script can be used to just login to Vault with approle.
# It return auth file with token on login command.
#
# Some information are printed to STDERR so you can using pipes
# with no problem.
#
# This script autentificate against Vault using AppRole and
# environment (CI/CD) Variables:
#   VAULT_ADDR          - address of the vault server
#   VAULT_ROLE_ID       - Role id of the approle auth
#   VAULT_SECRET_ID     - Secret if of the approle auth
#
# OR alternatively you can set VAULT_TOKEN instead of VAULT_*_ID
# and use TOKEN based Auth.
#
# Script args
#  -b    - basic path to search for environment (default /secret)
#  -p    - path to secret inside environment
#  -e    - environment name (default NONE)
#        - NONE environment mean, dont use environments at all
#        - you can use CI_.* as environment, then
#          environment is used from this variable
#          example "-e CI_ENVIRONMENT_SLUG"
#  -o    - output can be file or - for stdout (default stdout)
#  -f    - format of the output, shell, shellnq ,json or yaml (default shell)
#          shellnq means shell with no quotes
#  -s    - search for key, simple setup just get secret and
#          output content of the key (-f is ignored here)
#          Ideal to export files 
#
# Script Commands
#
#  login  - login to vault, create auth file with token
#  logout - revoke token and clear the auth file
#
# Autentification
#
# As we said this script using AppRole to autentificate against Vault
# It creates auth file and caches token to be reused on another run.
# If you run script 100 times it login only once to the Vault.
#
# If you want to logout from Vault you have to call logout command.
# Script automatically check if token is still alive. If token is expired
# it relogin again.
#
# More Examples:
# Default path construction
#   /<basic path>/<secret path>
#
# Use environments ( -e <my environment or CI variable> )
#   /<basic path/<environment name>/<secret path>
#
# Author: Robert Vojcik <robert@vojcik.net>
#
# END HELP_DESCRIPTION

function show_help {
    echo "Usage: $0 [-b][-e][-o][-f][-p][-s] [login|logout]"
    cat $0 | sed -n '/^# HELP_DESCRIPTION/,/^# END HELP_DESCRIPTION/p' | tail -n+2 | head -n-1 | sed 's/^#//'
    exit 1
}

function check_errors {
    if [ $errors -gt 0 ] ; then
        echo "$1" >&2
        exit 1
    fi
}

function vault_check_token {
    # Check token validity
    # VAULT_ADDR
    # VAULT_ROLE_ID
    # VAULT_SECRET_ID
    if ! [ -f $auth_file ]; then
        echo "ERROR: Unable to find auth_file, something went wrong" >&2
        exit 1
    fi
    vault_token=$(cat $auth_file)

    response=$(curl -L -s \
        --header "X-Vault-Token: $vault_token" \
        --request GET \
        $VAULT_ADDR/v1/auth/token/lookup-self)

    data=$(echo "$response" | jq -r '.data.ttl')

    if [[ "$data" == "null" ]] ; then
        echo "WARNING: Token expired or wrong. Trying to relogin..." >&2
        vault_login
    else
        echo "# Token looks valid (ttl: $data)" >&2
    fi
}

function vault_login {
    # Login to vault, create auth file
    # VAULT_ADDR
    # VAULT_ROLE_ID
    # VAULT_SECRET_ID
    # or VAULT_TOKEN

    # Zero VAULT_TOKEN, use APP-ROLE
    if [ -z $VAULT_TOKEN ] ; then 
        echo "# Logging into Vault with APPROLE ($VAULT_ADDR)" >&2
        response=$(curl -L -s \
            --request POST \
            --data "{\"role_id\":\"$VAULT_ROLE_ID\",\"secret_id\":\"$VAULT_SECRET_ID\"}" \
            $VAULT_ADDR/v1/auth/approle/login)
        vault_token=$(echo "$response" | jq -r .auth.client_token)

    else
        echo "# Logging into Vault using VAULT_TOKEN ($VAULT_ADDR)" >&2
        vault_token=$VAULT_TOKEN
    fi

    if [[ "n$vault_token" == "n" ]] || [[ "$vault_token" == "null" ]] ; then
        echo "ERROR: Unable to get Client Token. Auth failed" >&2
        exit 1
    fi

    if ! echo $vault_token > $auth_file ; then
        echo "ERROR: Unable to write to auth file ($auth_file)" >&2
        exit 1
    fi
}
function vault_get_secret {
    # secret_basic_path
    # environment
    # secret_path
    if ! [ -f $auth_file ]; then
        echo "ERROR: Unable to find auth_file, something went wrong" >&2
        exit 1
    fi
    vault_token=$(cat $auth_file)

    # Remove first slash
    basic_path=$(echo "$secret_basic_path" | sed 's#^/##')
    # Substitute second slash for data/ (KV v2)
    basic_path_v2=${basic_path/\//\/data/}
    # In case there are short path without slashes, add data at the end
    if ! echo "$basic_path_v2" | grep -q '/data/' ; then
        basic_path_v2=$basic_path/data
    fi
    
    response=$(curl -L -s \
        --header "X-Vault-Token: $vault_token" \
        --request GET \
        $VAULT_ADDR/v1/$basic_path/$environment/$secret_path)

    data=$(echo "$response" | jq '.data')

    if [[ "$data" == "null" ]] ; then

        # There is no data, maybe it's because it's KV2 storage
        response=$(curl -L -s \
            --header "X-Vault-Token: $vault_token" \
            --request GET \
            $VAULT_ADDR/v1/$basic_path_v2/$environment/$secret_path)

        data=$(echo "$response" | jq '.data.data')

        if [[ "$data" == "null" ]] ; then
            echo "ERROR: No secrets found" >&2
            exit 1
        fi
    fi
    
    # Validate output
    if ! echo "$data" | jq . &> /dev/null ; then
        echo "ERROR: There is some output but it's not valid JSON format" >&2
        echo " OUTPUT: $data" >&2
        exit 1
    fi

    # If we want just content of the specific key
    if [[ "$secret_key" != "" ]] ; then
        data=$(echo "$data" | jq -r ".[\"$secret_key\"]")
    fi

    echo "$data"
}

if [ $# -lt 1 ] ; then
    show_help
fi

#
# Pre Flight checks
# Check for basic tools we need
#
for util in jq curl ; do 
    errors=0
    if ! which $util &> /dev/null ; then
        echo "Missing util: $util"
        let errors++
    fi
done
check_errors "There are errors in preflight checks"

#
# Default Variables
#
secret_basic_path=/secret
output_format=shell
output_file="-"
environment_option="NONE"
auth_file="/tmp/vault-auth-file"

#
# Login and logout
#
if [[ "$1" == "login" ]] ; then
    vault_login
    echo "$auth_file"
    exit 0
elif [[ "$1" == "logout" ]]; then
    rm -f $auth_file
    exit 0
fi
#
# Parsing arguments
#
while getopts ":hb:p:e:o:f:s:" opt; do
    case $opt in
        b)
            secret_basic_path=$OPTARG
        ;;
        p)
            secret_path=$OPTARG
        ;;
        e)
            environment_option=$OPTARG
        ;;
        o)
            output_file=$OPTARG
        ;;
        f)
            output_format=$OPTARG
        ;;
        s)
            secret_key=$OPTARG
        ;;
        h)
            show_help
        ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            show_help
        ;;
        :)
            echo "Option -$OPTARG requires an argument!" >&2
            show_help
        ;;
    esac
done

#
# Set real Environment
#
if [[ "$environment_option" == "NONE" ]] ; then
    environment=""
elif [[ "$environment_option" =~ ^CI_.* ]] ; then
    environment=${!environment_option}
else
    environment=$environment_option
fi

#
# Control Important variables
#
if [ -z $VAULT_TOKEN ] ; then
    check_vars=("VAULT_ADDR" "secret_path" "VAULT_ROLE_ID" "VAULT_SECRET_ID")
else
    check_vars=("VAULT_ADDR" "secret_path")
fi
for variable in "${check_vars[@]}" ; do
    if [ -z ${!variable} ] ; then
        echo "ERROR: $variable is not set" >&2
        let errors++
    fi
done
check_errors "There are missing variables"

#
# Login to Vault with approle
#
if ! [ -f $auth_file ] ; then
    vault_login
else
    echo "# Using cached token" >&2
    vault_check_token
fi

#
# Retrieve secret
#
# Get Data from Vault
echo "# Retrieving secret (B:$secret_basic_path, E:$environment, S: $secret_path)" >&2
secret_data=$(vault_get_secret)

# Exit main loop when vault_get_secret returns non 0
if [ $? -gt 0 ] ; then
	exit 1
fi

if [[ "$secret_key" == "" ]] ; then
    #
    # Output Format
    #
    echo "# Format output ($output_format)" >&2
    if [[ "$output_format" == "shell" ]] ; then
        output_data=$(echo "$secret_data" | jq -r '. | to_entries | .[] | .key + "=\"" + .value + "\""')
    elif [[ "$output_format" == "shellnq" ]] ; then
        output_data=$(echo "$secret_data" | jq -r '. | to_entries | .[] | .key + "=" + .value')
    elif [[ "$output_format" == "yaml" ]] ; then
        output_data="---\n"$(echo "$secret_data" | jq -r '. | to_entries | .[] | .key + ": \"" + .value + "\""')
    elif [[ "$output_format" == "json" ]] ; then
        output_data="$secret_data"
    else
        echo "ERROR: Unknown output format ($output_format)" >&2
        exit 1
    fi
else
    output_data=$secret_data
fi

#
# Output Destination
#
if [[ "$output_file" == "-" ]] ; then
    echo -e -n "$output_data"
else
    if ! echo -e "$output_data" > $output_file ; then
        echo "Unable to write output to file: $output_file" >&2
        exit 1
    fi
fi
