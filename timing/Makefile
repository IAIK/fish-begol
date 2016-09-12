ITER=10

generate-timings:
	set -e && for n in 128 192 256 ; do \
		python timing.py lowmc-inst-$$n.txt -i $(ITER); \
	done

generate-graphs:
	set -e && for n in 128 192 256 ; do \
		octave timing.m $$n 128; \
	done

all: generate-timings generate-graphs
