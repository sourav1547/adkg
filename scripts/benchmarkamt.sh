#!/bin/bash
sh generate-qsdh-params.sh crs 500
sleep 2
BenchVSS crs 2 257 amt 5 5 5 amt/vssresults.csv
BenchAMT crs 2 4 10 2> amt/t1.txt
BenchAMT crs 3 7 10 2> amt/t2.txt
BenchAMT crs 6 16 10 2> amt/t5.txt
BenchAMT crs 12 34 10 2> amt/t11.txt
BenchAMT crs 22 64 10 2> amt/t21.txt
BenchAMT crs 34 100 10 2> amt/t33.txt