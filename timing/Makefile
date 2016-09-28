ITER?=100
MAXTHREADS?=$(shell grep "^processor"  /proc/cpuinfo | wc -l)

timings-plain:
	python timing.py lowmc-inst-128.txt -k 128 -i $(ITER)
	python timing.py lowmc-inst-192.txt -k 128 -i $(ITER)
	python timing.py lowmc-inst-192.txt -k 192 -i $(ITER)
	python timing.py lowmc-inst-256.txt -k 128 -i $(ITER)
	python timing.py lowmc-inst-256.txt -k 256 -i $(ITER)
	python timing.py lowmc-inst-512.txt -k 128 -i $(ITER)
	python timing.py lowmc-inst-512.txt -k 512 -i $(ITER)

timings-pq:
	python timing.py pq-lowmc-inst-256.txt -k 256 -i $(ITER) -p pq-timings
	# python timing.py pq-lowmc-inst-384.txt -k 256 -i $(ITER) -p pq-timings
	python timing.py pq-lowmc-inst-384-384.txt -k 384 -i $(ITER) -p pq-timings
	python timing.py pq-lowmc-inst-512-512.txt -k 512 -i $(ITER) -p pq-timings

timings-omp:
	# before running this benchmark, make sure to disable HyperThreading as it
	# adds a lot of noise.
	set -ex && for n in $(shell seq 1 $(MAXTHREADS)) ; do \
		env OMP_NUM_THREADS=$$n \
			python timing.py lowmc-inst-128.txt -i $(ITER) -p omp-timings-$$n -x ../mpc_lowmc_openmp; \
	done

timings: timings-plain timings-pq timings-omp

graphs-plain:
	python graphs.py -p timings default \
		--fs-blocksize 128 --fs-keysize 128 --fs-annotate 12-26 \
		--bg-blocksize 128 --bg-keysize 128 --bg-annotate 12-26

graphs-pq:
	python graphs.py -p pq-timings default \
		--fs-blocksize 256 --fs-keysize 256 --fs-annotate 20-31 \
		--bg-blocksize 256 --bg-keysize 256 --bg-annotate 20-31

graphs-omp:
	python graphs.py -p omp-timings omp --bg-blocksize 128 --bg-keysize 128 -t $(MAXTHREADS)

graphs-qh:
	python graphs.py -p timings qH \
		--bg-blocksize 128 --bg-keysize 128 --bg-annotate 12-26 \
		--fs-annotate 12-26 \
		128 192 256
	python graphs.py -p pq-timings qH \
		--bg-blocksize 256 --bg-keysize 256 --bg-annotate 20-31 \
		--fs-annotate 20-31 \
		256 384 512

graphs: graphs-plain graphs-pq graphs-omp graphs-qh

all: timings-plain graphs-plain
