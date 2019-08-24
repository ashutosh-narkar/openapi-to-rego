#!/usr/bin/env bash

SRC_DIR=$(dirname "${BASH_SOURCE}")/..
source $SRC_DIR/scripts/utils.sh

function rego::check_fmt() {
    exec 5>&1
    exit_code=0
    for pkg in $(rego::go_packages); do
        for file in $(rego::go_files_in_package $pkg); do
            __diff=$(gofmt -d $file | tee >(cat - >&5))
            if [ ! -z "$__diff" ]; then
                exit_code=1
            fi
        done
    done
    exit $exit_code
}

rego::check_fmt
