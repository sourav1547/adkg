#!/bin/bash
rm ../.benchmarks/Linux-CPython-3.7-64bit/0001_pclog.json
cd ..
pytest --benchmark-save=pclog benchmark/test_benchmark_poly_commit_log.py