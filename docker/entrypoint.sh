#!/bin/sh
output=${CONFIG_OUTPUT:-"/etc/cylonix"}
generate()
{
    output=$2
    mkdir -p $output
    find "$1" -follow -type f  -print | while read -r f ; do
        f=$(echo $f | awk -F '/' '{print $NF}')
        echo Generate "$f" from template with environmental variables.
        envsubst < $1/$f > $output/$f
    done
}

# Resolve _FILE env vars (standard Docker secrets pattern). For any env var
# ending in _FILE whose value is a readable file path, load the file's
# contents into the same-named env var without the suffix, unless that var
# is already set. Trailing newlines are stripped.
#
# Skip _FILE vars whose corresponding non-_FILE name is a real path the app
# expects (e.g. SEND_EMAIL_SERVICE_ACCOUNT_FILE, APPLE_LOGIN_CLIENT_SECRET):
# those are passed through unchanged.
resolve_file_env() {
    for name_file in $(env | sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*_FILE\)=.*/\1/p'); do
        name=${name_file%_FILE}
        eval "path=\${$name_file}"
        case "$name_file" in
            SEND_EMAIL_SERVICE_ACCOUNT_FILE) continue ;;
        esac
        eval "current=\${$name-}"
        if [ -n "$current" ]; then continue; fi
        if [ -z "$path" ] || [ ! -r "$path" ]; then
            echo "warn: $name_file=$path not readable, skipping" >&2
            continue
        fi
        value=$(cat "$path")
        export "$name=$value"
        echo "loaded $name from $path ($(printf '%s' "$value" | wc -c | tr -d ' ') bytes)"
    done
}

# Set env with defaults.
. /opt/defaults.sh

# Load secrets from files referenced by *_FILE env vars.
resolve_file_env

# Generate configs with templates and env settings.
generate /opt/templates $output
exec "$@"