#!/bin/bash

MYST_EXEC="$1"
ROOTFS="$2"
OPTS="$3"
PACKAGES="$4"

cnt=0
pass=0
while read -r package; do
	if [[ "$package" != \#* ]]; then
		((++cnt))
		echo "****************************************"
		echo "Running Tests on Package #$cnt: $package"
		# shellcheck disable=SC2086
		${MYST_EXEC} "${ROOTFS}" ${OPTS} --app-config-path config.json /usr/local/bin/python3 -m pytest "$package" && ((++pass))
	fi
done < "${PACKAGES}"

echo "Result - ${pass} Out of ${cnt} Packages Passed: ${PACKAGES}"
if [[ "$pass" != "$cnt" ]]; then
	exit 1
fi
exit 0
