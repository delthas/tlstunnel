#!/bin/sh -eu

cmd=$1
domain=$2
token=$4

find_zone() {
	scw dns zone list -o json | jq -r 'map(.domain) | join ("\n")' | while read name; do
		if [ "$domain" = "$name" ] || [ "${domain%.$name}" != "$domain" ]; then
			echo "$name"
		fi
	done
}

zone=$(find_zone)
if [ -z "$zone" ]; then
	echo >&2 "Cannot find apprioriate zone for $domain"
	exit 1
fi

challenge_domain="_acme-challenge.$domain"

case "$cmd" in
deploy_challenge)
	scw dns record set "$zone" "name=$challenge_domain." ttl=300 type=TXT "values.0=$token" >/dev/null
	;;
clean_challenge)
	scw dns record delete "$zone" type=TXT "name=${challenge_domain%.$zone}" 'data="'"$token"'"'
	;;
*)
	echo >&2 "Unrecognized subcommand"
	exit 1
	;;
esac
