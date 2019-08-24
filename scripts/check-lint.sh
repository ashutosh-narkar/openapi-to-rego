#!/usr/bin/env bash

SRC_DIR=$(
    dir=$(dirname "${BASH_SOURCE}")/..
    cd "$dir"
    pwd
)
source $SRC_DIR/scripts/utils.sh


function rego::check_lint() {
    exec 5>&1
    exit_code=0
    for pkg in $(rego::go_packages); do
        __output=$(golint $pkg | tee >(cat - >&5))
        if [ ! -z "$__output" ]; then
            exit_code=1
        fi
    done
    exit $exit_code
}

rego::check_lint
