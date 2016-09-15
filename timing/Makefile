ITER?=10

generate-timings:
	set -e && for n in 128 192 256 ; do \
		python timing.py lowmc-inst-$$n.txt -i $(ITER); \
	done
	set -e && for n in 256 384 512 ; do \
		python timing.py pq-lowmc-inst-$$n.txt -i $(ITER) -p pq-timings; \
	done

generate-graphs:
	set -e && for n in 128 192 256 ; do \
		octave timing.m $$n 128 timings; \
	done
	set -e && for n in 256 384 512 ; do \
		octave timing.m $$n 128 pq-timings; \
	done


all: generate-timings generate-graphs
