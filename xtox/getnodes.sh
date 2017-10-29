#!/bin/sh

set -x

URL=https://nodes.tox.chat/json

curl "$URL" > toxnodes_raw.json

json_reformat < toxnodes_raw.json > toxnodes.json

go-bindata -nocompress -pkg xtox -o toxnodes_assets.go toxnodes.json

