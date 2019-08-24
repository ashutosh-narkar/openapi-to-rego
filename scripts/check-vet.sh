#!/usr/bin/env bash

SRC_DIR=$(
    dir=$(dirname "${BASH_SOURCE}")/..
    cd "$dir"
    pwd
)
source $SRC_DIR/scripts/utils.sh

function rego::check_vet() {
    exec 5>&1
    rc=0
    exit_code=0
    for pkg in $(rego::go_packages); do
        go vet $pkg || rc=$?
        if [[ $rc != 0 ]]; then
            exit_code=1
        fi
    done
    exit $exit_code
}

rego::check_vet
