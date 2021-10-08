#!/bin/bash
set -e

while read -r package; do
	if [[ "$package" != \#* ]]; then
		cd "$package" \
		&& pip install -r dev_requirements.txt \
 		&& pip install -e .
	fi
done < /packages.txt
