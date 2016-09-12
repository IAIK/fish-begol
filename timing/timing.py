import argparse
import subprocess
import os
import numpy as np
import h5py

def main():
  args = parse_args()
  k = args.keysize
  with open(args.filename) as f:
    octarg = []
    all_timings_fs = []
    all_timings_bg = []
    for line in f.readlines():
      if line.rstrip():
        m, n, r = get_params(line)
        fname = "{0}-{1}".format(m, r)
        octarg.append(fname)

        with open(fname, "w") as timings:
          subprocess.Popen([args.executable, str(m), str(n), str(r), str(k),
                            str(args.iterations)], stdout=timings).wait()

        with open(fname, "r") as timings:
          data = timings.read()
        os.unlink(fname)

        mat = []
        for line in data.split("\n"):
          line = line.replace('{', '')
          line = line.replace('}', '')
          if not len(line):
            continue

          mat.append(map(int, line.split(',')))

        fs = np.array(mat[:len(mat) / 2])
        bg = np.array(mat[len(mat) / 2:])

        all_timings_fs.append(np.sum(fs, axis=0) / float(args.iterations))
        all_timings_bg.append(np.sum(bg, axis=0) / float(args.iterations))

    with h5py.File('timings-{0}-{1}.mat'.format(n, k), 'w') as timings:
        timings.create_dataset("fis_sum", data=np.array(all_timings_fs))
        timings.create_dataset("bg_sum", data=np.array(all_timings_bg))
        timings.create_dataset('labels', data=octarg)

def get_params(line):
  l = line.split()
  d = dict(zip(l[::2], l[1::2]))
  m = d['m:']
  n = d['blocksize:']
  r = d['ANDdepth:']
  return m, n, r

def parse_args():
  parser = argparse.ArgumentParser(description='Process LowMC Timing Args.')
  parser.add_argument("filename", help="the filename of the lowmc instances")
  parser.add_argument("-k", "--keysize", help="the LowMC keysize", type=int,
                      choices=[128, 192, 256, 384, 448, 512], default=128)
  parser.add_argument("-x", "--executable", help="the LowMC MPC executable",
                      default="../mpc_lowmc")
  parser.add_argument("-i", "--iterations", help="number of iterations",
                      default="100")
  parser.add_argument("-o", "--octavescript", help="the name of the octave script",
                      default="timing.m")
  args = parser.parse_args()
  return args

if __name__ == "__main__":
    main()
