#!/bin/sh

set -e

while true;
do
    dlv --check-go-version=false --listen 0.0.0.0:2345 --headless=true --continue --accept-multiclient debug cmd/authelia/*.go -- --config /config/configuration.yml
    sleep 10
done
