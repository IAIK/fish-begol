ITER?=10
MAXTHREADS?=8

timings-plain:
	python timing.py lowmc-inst-128.txt -k 128 -i $(ITER)
	python timing.py lowmc-inst-256.txt -k 256 -i $(ITER)

timings-pq:
	python timing.py pq-lowmc-inst-384.txt -k 256 -i $(ITER) -p pq-timings
	python timing.py pq-lowmc-inst-256.txt -k 256 -i $(ITER) -p pq-timings

timings-omp:
	set -e && for n in $(shell seq 1 $(MAXTHREADS)) ; do \
		env OMP_NUM_THREADS=$$n \
			python timing.py lowmc-inst-256.txt -i $(ITER) -p omp-timings-$$n -x ../mpc_lowmc_openmp; \
	done

timings: timings-plain timings-pq timings-omp

graphs-plain:
	python graphs.py -p timings --fs-blocksize 256 --fs-keysize 256 --bg-blocksize 128 --bg-keysize 128

graphs-pq:
	python graphs.py -p pq-timings --fs-blocksize 384 --fs-keysize 256 --bg-blocksize 256 --bg-keysize 256

graphs-omp:
	python graphs.py 256 -k 128 -p omp-timings -o -t $(MAXTHREADS)

all: timings-plain graphs-plain
