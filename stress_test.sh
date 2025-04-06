#!/usr/bin/env bash

cargo b --release

./target/release/ooclutter server -p 8080 > /dev/null 2> /dev/null &

start_time=$(date +%S.%N)

parallel -N0 ./target/release/ooclutter client -p 8080 ::: {1..1024} 2> /dev/null

end_time=$(date +%S.%N)

RPS=$(python3 -c "print(1 / (($end_time - $start_time) / 1024.0))")
echo "$RPS r/s"

pkill -9 ooclutter