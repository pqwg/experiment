#!/bin/bash -e

ROOT="$(realpath $(dirname $0))"

EXPERIMENTS=(pq-x25519mock pq-dagger-mceliece pq-rkem-mceliece)

function build_experiment {
	local experiment=$1
	local configfile="${ROOT}/wgtest/wgtest-${experiment}/vars"
	if ! [ -e "$configfile" ]; then
		echo "Invalid argument, ${experiment} is not valid"
		exit 1
	fi

	source "$configfile"

	local experiment_dir="${ROOT}/experiments/${experiment}"
	mkdir -p "${experiment_dir}"

	pushd "${ROOT}/wireguard-linux-compat/src"
	rm -f kem rkem
	ln -s kems/$KEM kem
	ln -s rkems/$RKEM rkem
	make -B -j$(nproc)
	cp "wireguard.ko" "${experiment_dir}"
	popd

	pushd "${ROOT}/wireguard-tools/src"
	rm -f kem rkem
	ln -s kems/$KEM kem
	ln -s rkems/$RKEM rkem
	make -B -j3 wg
	cp "wg" "${experiment_dir}"
	cp "wg-quick/linux.bash" "${experiment_dir}/wg-quick"
	popd

	cp -r "${ROOT}/resources/"* "${experiment_dir}"

}

rm -rf "${ROOT}/experiments"
mkdir -p "${ROOT}/experiments"

for experiment in ${EXPERIMENTS[@]}; do
	echo "Building ${experiment}"

	build_experiment $experiment

done
