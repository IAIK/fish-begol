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
		python graphs.py -n $$n -k 128 -p timings; \
	done
	set -e && for n in 256 384 512 ; do \
		python graphs.py -n $$n -k 128 -p pq-timings; \
	done


all: generate-timings generate-graphs
