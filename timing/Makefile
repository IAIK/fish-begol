ITER?=100
MAXTHREADS?=$(shell grep "^processor"  /proc/cpuinfo | wc -l)

PQOPTS=-p pq-timings -x ../mpc_lowmc_pq

timings-preq:
	python3 timing.py lowmc-inst-128-128-128.txt -k 128 -i $(ITER)
	python3 timing.py lowmc-inst-192-192-192.txt -k 192 -i $(ITER)
	python3 timing.py lowmc-inst-256-256-256.txt -k 256 -i $(ITER)
	python3 timing.py lowmc-inst-512-512-512.txt -k 512 -i $(ITER)

timings-postq:
	python3 timing.py pq-lowmc-inst-256-256-256.txt -k 256 -i $(ITER) $(PQOPTS)
	python3 timing.py pq-lowmc-inst-384-384-384.txt -k 384 -i $(ITER) $(PQOPTS)
	python3 timing.py pq-lowmc-inst-512-512-512.txt -k 512 -i $(ITER) $(PQOPTS)

timings-omp:
	# before running this benchmark, make sure to disable HyperThreading as it
	# adds a lot of noise.
	set -ex && for n in $(shell seq 1 $(MAXTHREADS)) ; do \
		env OMP_NUM_THREADS=$$n \
			python3 timing.py lowmc-inst-128-128-128.txt -i $(ITER) -p omp-timings-$$n -x ../mpc_lowmc_openmp; \
	done

timings: timings-preq timings-postq timings-omp

graphs-preq:
	python3 graphs.py -p timings default \
		--fs-blocksize 128 --fs-keysize 128 --fs-annotate 12-26 \
		--bg-blocksize 128 --bg-keysize 128 --bg-annotate 12-26

graphs-postq:
	python3 graphs.py -p pq-timings default \
		--fs-blocksize 256 --fs-keysize 256 --fs-annotate 20-31 \
		--bg-blocksize 256 --bg-keysize 256 --bg-annotate 20-31 \
		--sha-proof 237 --sha-verify 137 --sha-size 2672.484375

graphs-omp:
	python3 graphs.py -p omp-timings omp --bg-blocksize 128 --bg-keysize 128 -t $(MAXTHREADS)

graphs-qh:
	python3 graphs.py -p timings qH \
		--bg-blocksize 128 --bg-keysize 128 --bg-annotate 12-26 \
		--fs-annotate "128-128-12-26 256-256-26-18 512-512-34-37" \
		--annotate-extreme \
		128 256 512
	python3 graphs.py -p pq-timings qH \
		--bg-blocksize 256 --bg-keysize 256 --bg-annotate 20-31 \
		--fs-annotate "256-256-20-31 384-384-30-33 512-512-34-37" \
		--annotate-extreme \
		256 384 512

graphs: graphs-preq graphs-postq graphs-omp graphs-qh

all: timings-plain graphs-plain
