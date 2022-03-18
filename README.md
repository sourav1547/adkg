# Prototype implementation of Asynchronous Distributed Key Generation

This library implements the Asynchronous Distributed Key Generation protocol from the paper
https://eprint.iacr.org/2021/1591 

NOTE: This is a research implementation and may contain security issues. Do not use this for production.


# Running and benchmarking `adkg`
First, docker-compose will need to be installed if it has not been previously:

1. Install `Docker`_. (For Linux, see `Manage Docker as a non-root user`_) to
   run ``docker`` without ``sudo``.)

2. Install `docker-compose`.

Next, the image will need to be built  (this will likely take a while)
```
$ docker-compose build adkg
```

## Running tests and generating data points for adkg

You need to start a shell session in a container. The first run will take longer if the docker image hasn't already been built:
```
$ docker-compose run --rm adkg bash
```

Then, to test the `adkg` code locally, i.e., multiple thread in a single docker container, you need to run
```
$ pytest tests/test_adkg.py
```



### Debug using `vscode`
To debug the code using `vscode`, first uncomment the following from `Dockerfile`
```
# RUN pip install debugpy
# ENTRYPOINT [ "python", "-m", "debugpy", "--listen", "0.0.0.0:5678", "--wait-for-client", "-m"]
```

Rebuild the `docker` images by runnning
```
docker-compose build adkg
```

Then `debug` by running the following command. Make sure to run the debugging in `vscode` after executing the following command. 
```
docker-compose run -p 5678:5678 adkg pytest tests/test_adkg.py 
```

## Running in AWS instances

For remote deployment first build using
```
docker build -t adkg-remote . --build-arg BUILD=dev
```

## Miscelleneous instructions
```
$ docker-compose build adkg
$ docker-compose run -p 5678:5678 adkg pytest tests/test_adkg.py 
$ docker-compose run adkg -it
```

## Todo:
- [ ] Clean the optimistic RBC code
- [ ] Take reconstruction threshold and group as a public parameter.
- [ ] Merge all configurations into a single `branch`
- [ ] Include DCR-ACSS to the codebase.

## Branches and description
`abaopt`
- `bls12381` curve, low threshold, implements hbACSS0
- This branch implements custom serialization for ACSS messages

`abaopt-ed`
- `ed25519` curve, low threshold, implements hbACSS0
- This branch implements custom serialization for ACSS messages


`serial-high`
- `bls12381` curve, high threshold, implements Haven
- This branch implements custom serialization for ACSS messages

`serial-high-ed`
- `ed25519` curve, high threshold, implements Haven
- This branch implements custom serialization for ACSS messages


## Historical Remarks.
This library is built upon the open-source `hbACSS` library from https://github.com/tyurek/hbACSS, which itself is built upon the open source implementation of the `HoneyBadgerBFT` protocol https://github.com/amiller/HoneyBadgerBFT 



# README from hbACSS

# Running and benchmarking hbACSS

## Setup

First, docker-compose will need to be installed if it has not been previously:

1. Install `Docker`_. (For Linux, see `Manage Docker as a non-root user`_) to
   run ``docker`` without ``sudo``.)

2. Install `docker-compose`.

Next, the image will need to be built  (this will likely take a while)
```
$ docker-compose build honeybadgermpc
```

## Running benchmarks and generating data points for hbACSS

You need to start a shell session in a container. The first run will take longer if the docker image hasn't already been built:
```
$ docker-compose run --rm honeybadgermpc bash
```

Then, to rerun our benchmarks, you can use:
```
$ pytest --benchmark-save=hbavss_dummy_pcl --benchmark-min-rounds=3 --benchmark-warmup-iterations=0 benchmark/test_benchmark_hbavss_loglin.py
$ pytest --benchmark-save=pcl_detailed --benchmark-min-rounds=3 --benchmark-warmup-iterations=0 benchmark/test_benchmark_poly_commit_log.py
$ pytest --benchmark-save=hbacss2_dummy_pcl --benchmark-min-rounds=3 --benchmark-warmup-iterations=0 benchmark/test_benchmark_hbacss2_dummy_pcl.py
```

This will save the results under `.benmarks` in the same format as [DataWinterfell](../Datawinterfell).
The last benchmark may crash if your machine does not have sufficient memory. If so, try removing 22 and 42 from short_param_list_t in test_benchmark_hbacss2_dummy_pcl.py

## Generating graphs

We've included the benchmarks that were used in our paper in the [DataWinterfell](../Datawinterfell) folder. Within Datawinterfell, the [amt_benchmarks](../Datawinterfell/amt_benchmarks) folder contains the benchmarking results for [AMT](https://github.com/alinush/libpolycrypto), which is obtained with the described modifications in our paper. The [Linux-CPython-3.7-64bit](../Datawinterfell/Linux-CPython-3.7-64bit) folder contains the benchmarking results we obtained from our own code. 

Calling the following graphing script will recreate the plots from our paper:
```
$ python polycommit_loglin_gengraphs.py
```
Similarly, the following will generate graphs from the local benchmarks generated above and place them in the gen_graphs folder:
```
$ python gengraphs.py
```
this script will look for .benchmarks/amt_benchmarks/vssresults.csv to plot AMT results alongside ours. If this file is not found, it will only plot our results.
