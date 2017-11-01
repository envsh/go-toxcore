#!/bin/sh

set -x

URL=https://nodes.tox.chat/json

curl "$URL" > toxnodes_raw.json

json_reformat < toxnodes_raw.json > toxnodes.json

go-bindata -nocompress -pkg xtox -o toxnodes_assets.go toxnodes.json

update_date=$(date +%Y%m%d)

echo -e "package xtox\nconst toxnodes_last_update = \"$update_date\"\n" > toxnodes_last_update.go
