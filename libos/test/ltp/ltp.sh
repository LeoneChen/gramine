#!/bin/bash

SCRIPT_DIR=$(realpath $(dirname $0))

while IFS= read -r line; do
    line=$(echo "$line" | xargs)
    if [[ -z "$line" || "$line" =~ ^# ]]; then
        continue
    fi

    name=$(echo "$line" | cut -d' ' -f1)
    cmd=$(echo "$line" | cut -d' ' -f2-)

    echo ""
    echo "===== LTP TESTCASE ${name}: ${cmd} ====="
    echo ""
    timeout -k 5 -v 120 gramine-sgx ltp /run.sh ${cmd}
done < ${SCRIPT_DIR}/src/runtest/syscalls
