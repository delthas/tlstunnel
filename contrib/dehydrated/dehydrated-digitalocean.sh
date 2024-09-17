#!/bin/sh -eu

cmd=$1
domain=$2
token=$4

find_zone() {
	doctl compute domain list --no-header --format Domain | while read name; do
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
	doctl compute domain records create "$zone" --record-name "$challenge_domain." --record-ttl 300 --record-type TXT --record-data "$token"
	;;
clean_challenge)
	doctl compute domain records list "$zone" --no-header --format ID,Type,Name,Data | while read rec_id rec_type rec_name rec_data; do
		if [ "$rec_type" = TXT ] && [ "$rec_name.$zone" = "$challenge_domain" ] && [ "$rec_data" = "$token" ]; then
			echo "Deleting record $rec_id"
			doctl compute domain records delete --force "$zone" "$rec_id"
			break
		fi
	done
	;;
*)
	echo >&2 "Unrecognized subcommand"
	exit 1
	;;
esac
