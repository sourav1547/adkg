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
