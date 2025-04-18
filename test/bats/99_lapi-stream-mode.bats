#!/usr/bin/env bats

set -u

setup_file() {
    load "../lib/setup_file.sh"
    ./instance-data load
    ./instance-crowdsec start
    API_KEY=$(cscli bouncers add testbouncer -o raw)
    export API_KEY
}

teardown_file() {
    load "../lib/teardown_file.sh"
}

setup() {
    load "../lib/setup.sh"
}

#----------

@test "adding decisions for multiple ips" {
    rune -0 cscli decisions add -i '1111:2222:3333:4444:5555:6666:7777:8888'
    assert_stderr --partial 'Decision successfully added'
    rune -0 cscli decisions add -i '1.2.3.4'
    assert_stderr --partial 'Decision successfully added'
    rune -0 cscli decisions add -r '1.2.4.0/24'
    assert_stderr --partial 'Decision successfully added'
}

@test "stream start" {
    rune -0 curl-with-key "/v1/decisions/stream?startup=true"
    if is_db_mysql; then sleep 3; fi
    rune -0 jq -r '.new' <(output)
    assert_output --partial '1111:2222:3333:4444:5555:6666:7777:8888'
    assert_output --partial '1.2.3.4'
    assert_output --partial '1.2.4.0/24'
}

@test "stream cont (add)" {
    rune -0 cscli decisions add -i '1.2.3.5'
    if is_db_mysql; then sleep 3; fi
    rune -0 curl-with-key "/v1/decisions/stream"
    rune -0 jq -r '.new' <(output)
    assert_output --partial '1.2.3.5'
}

@test "stream cont (del)" {
    rune -0 cscli decisions delete -i '1.2.3.4'
    if is_db_mysql; then sleep 3; fi
    rune -0 curl-with-key "/v1/decisions/stream"
    rune -0 jq -r '.deleted' <(output)
    assert_output --partial '1.2.3.4'
}

@test "stream restart" {
    rune -0 curl-with-key "/v1/decisions/stream?startup=true"
    api_out=${output}
    rune -0 jq -r '.deleted' <(output)
    assert_output --partial '1.2.3.4'
    output=${api_out}
    rune -0 jq -r '.new' <(output)
    assert_output --partial '1111:2222:3333:4444:5555:6666:7777:8888'
    assert_output --partial '1.2.3.5'
    assert_output --partial '1.2.4.0/24'
}
