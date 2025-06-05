#!/bin/sh

for ns in $(ip netns list); do
	ip netns del $ns
done
