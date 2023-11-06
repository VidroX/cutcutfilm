#!/bin/bash
if ! test -f supergraph-config.yaml; then
    echo "Please create supergraph-config.yaml file"
    exit 1
fi

if test -f services/gateway/.env; then
    export $(grep -v '^#' services/gateway/.env | xargs)
fi

if ! command -v rover &> /dev/null
then
    echo "Installing Apollo Rover CLI"
    curl -sSL https://rover.apollo.dev/nix/latest | sh
    echo "Apollo Rover CLI has been installed successfully!"
fi

export APOLLO_ELV2_LICENSE=accept
export APOLLO_TELEMETRY_DISABLED=1

if [[ -z "${USER_SERVICE_LOCATION}" ]]; then
    echo "Missing USER_SERVICE_LOCATION environment variable"
    exit 1
fi

USER_SERVICE_LOCATION=$(echo $USER_SERVICE_LOCATION | tr -d '\n\t\r')

sed "s|{USER_SERVICE_LOCATION}|${USER_SERVICE_LOCATION}|g" supergraph-config.yaml > supergraph-config.compiled.yaml

~/.rover/bin/rover supergraph compose --config ./supergraph-config.compiled.yaml --output services/gateway/supergraph.graphql

rm supergraph-config.compiled.yaml