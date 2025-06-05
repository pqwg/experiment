#!/bin/sh

./build.sh

for d in experiments/*; do
	pushd $d
	./run.sh
	popd
done
