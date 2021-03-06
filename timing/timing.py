#!/usr/bin/python3

import argparse
import subprocess
import os
import numpy as np
import h5py


def fix_h5py_strings(strings):
    return [s.encode('utf-8') for s in strings]


def compute_size(data):
    return data[:, 12] / 1024.0


def compute_gen(data):
    return np.sum(data[:, 0:3], axis=1) / 1000.0


def compute_sign(data):
    return np.sum(data[:, 3:8], axis=1) / 1000.0


def compute_verify(data):
    return np.sum(data[:, 8:12], axis=1) / 1000.0


def main():
  args = parse_args()
  k = args.keysize
  with open(args.filename) as f:
    all_timings_fs = []
    all_timings_bg = []
    all_timings_fs_median = []
    all_timings_bg_median = []
    all_timings_fs_mean = []
    all_timings_bg_mean = []

    labels = []

    for line in f.readlines():
      if line.rstrip():
        m, n, r = get_params(line)
        fname = '{0}-{1}'.format(m, r)
        labels.append(fname)

        with open(fname, 'w') as timings:
          subprocess.Popen([args.executable, str(m), str(n), str(r), str(k),
                            str(args.iterations)], stdout=timings).wait()

        with open(fname, 'r') as timings:
          data = timings.read()
        os.unlink(fname)

        mat = []
        for line in data.split('\n'):
          line = line.replace('{', '')
          line = line.replace('}', '')
          if not len(line):
            continue

          mat.append(list(map(int, line.split(','))))

        if args.begol:
            fs = np.array(mat[:len(mat) / 2])
            bg = np.array(mat[len(mat) / 2:])
        else:
            fs = np.array(mat)

        all_timings_fs.append(np.mean(fs, axis=0))

        if args.begol:
            all_timings_bg.append(np.mean(bg, axis=0))

        fs_size = compute_size(fs)
        fs_gen = compute_gen(fs)
        fs_sign = compute_sign(fs)
        fs_verify = compute_verify(fs)
        all_timings_fs_median.append(list(map(np.median, [fs_gen, fs_sign, fs_verify,
            fs_size])))
        all_timings_fs_mean.append(list(map(np.mean, [fs_gen, fs_sign, fs_verify,
            fs_size])))

        if args.begol:
            bg_size = compute_size(bg)
            bg_gen = compute_gen(bg)
            bg_sign = compute_sign(bg)
            bg_verify = compute_verify(bg)
            all_timings_bg_median.append(list(map(np.median, [bg_gen, bg_sign, bg_verify,
                bg_size])))
            all_timings_bg_mean.append(list(map(np.mean, [bg_gen, bg_sign, bg_verify,
                bg_size])))

    with h5py.File('{0}-{1}-{2}.mat'.format(args.prefix, n, k), 'w') as timings:
        timings.create_dataset('fis_sum', data=np.array(all_timings_fs))
        timings.create_dataset('fis_median', data=np.array(all_timings_fs_median))
        timings.create_dataset('fis_mean', data=np.array(all_timings_fs_mean))
        if args.begol:
            timings.create_dataset('bg_sum', data=np.array(all_timings_bg))
            timings.create_dataset('bg_median', data=np.array(all_timings_bg_median))
            timings.create_dataset('bg_mean', data=np.array(all_timings_bg_mean))
        timings.create_dataset('labels', data=fix_h5py_strings(labels))


def get_params(line):
  l = line.split()
  d = dict(zip(l[::2], l[1::2]))
  m = d['m:']
  n = d['blocksize:']
  r = d['ANDdepth:']
  return m, n, r


def parse_args():
  parser = argparse.ArgumentParser(description='Process LowMC Timing Args.')
  parser.add_argument('filename', help='the filename of the lowmc instances')
  parser.add_argument('-k', '--keysize', help='the LowMC keysize', type=int,
                      choices=[128, 192, 256, 384, 448, 512], default=128)
  parser.add_argument('-x', '--executable', help='the LowMC MPC executable',
                      default='../mpc_lowmc')
  parser.add_argument('-i', '--iterations', help='number of iterations',
                      default='100')
  parser.add_argument('-p', '--prefix', help='prefix of mat files',
                      default='timings')
  parser.add_argument('-b', '--begol', help='alsp time Begol', default=False,
                      action='store_true')
  args = parser.parse_args()
  return args


if __name__ == '__main__':
    main()
