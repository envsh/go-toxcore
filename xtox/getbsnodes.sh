#!/bin/sh

set -x

URL=https://nodes.tox.chat/json

curl "$URL" > toxbsnodes_raw.json

json_reformat < toxbsnodes_raw.json > toxbsnodes.json

go-bindata -nocompress -pkg xtox -o toxbsnodes_assets.go toxbsnodes.json

update_date=$(date +%Y%m%d)

echo -e "package xtox\nconst toxnodes_last_update = \"$update_date\"\n" > toxnodes_last_update.go
