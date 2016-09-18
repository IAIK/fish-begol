ITER?=10
MAXTHREADS?=8

timings-plain:
	set -e && for n in 128 192 256 ; do \
		python timing.py lowmc-inst-$$n.txt -i $(ITER); \
	done

timings-pq:
	set -e && for n in 256 384 512 ; do \
		python timing.py pq-lowmc-inst-$$n.txt -i $(ITER) -p pq-timings; \
	done

timings-omp:
	set -e && for n in $(shell seq 1 $(MAXTHREADS)) ; do \
		env OMP_NUM_THREADS=$$n \
			python timing.py lowmc-inst-256.txt -i $(ITER) -p omp-timings-$$n -x ../mpc_lowmc_openmp; \
	done

timings: timings-plain timings-pq timings-omp

graphs:
	set -e && for n in 128 192 256 ; do \
		python graphs.py -n $$n -k 128 -p timings; \
	done

graphs-pq:
	set -e && for n in 256 384 512 ; do \
		python graphs.py -n $$n -k 128 -p pq-timings; \
	done

graphs-omp:
	python graphs.py -n 256 -k 128 -p omp-timings -o -t $(MAXTHREADS)

all: timings graphs
