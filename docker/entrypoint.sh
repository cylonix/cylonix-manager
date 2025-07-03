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

# Set env with defaults.
. /opt/defaults.sh

# Generate configs with templates and env settings.
generate /opt/templates $output
exec "$@"