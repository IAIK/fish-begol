import argparse
import h5py
import numpy as np
import matplotlib
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns


def compute_size(data):
  return data[:, 12] / 1024


def compute_sign(data):
  return np.sum(data[:, 3:7] / 1000, axis=1)


def compute_verify(data):
  return np.sum(data[:, 8:12] / 1000, axis=1)


def create_graph(prefix, n, k, data, labels):
  data = np.array(data)

  size = compute_size(data)
  sign = compute_sign(data)
  verify = compute_verify(data)

  df = pd.DataFrame({
      'sign': pd.Series(sign, index=labels),
      'verify': pd.Series(verify, index=labels),
      'size': pd.Series(size, index=labels)
  })

  plt.figure(figsize=(6, 6 * 3 / 4.0))
  ax = df.plot(secondary_y=['size'], mark_right=False, marker='>',
               markersize=6, linewidth=2.5, legend=False)

  # title and labels
  ax.set_title('LowMC Timing n={0} k={1} - Parameters [m]-[r]'.format(n, k))
  ax.set_ylabel('Time [ms]')
  ax.set_xlabel('')
  ax.right_ax.set_ylabel('Size [kB]')

  ax.set_xticks(range(len(labels)))
  ax.set_xticklabels(labels, rotation=45, fontsize=8)

  # grid
  ax.grid(True, axis='y')

  # legend
  handles, labels = ax.get_legend_handles_labels()
  handles_size, labels_size = ax.right_ax.get_legend_handles_labels()
  plt.legend(handles + handles_size, labels + labels_size, loc='upper center')

  plt.savefig('{0}-{1}-{2}.eps'.format(prefix, n, k))
  plt.savefig('{0}-{1}-{2}.png'.format(prefix, n, k))


def create_omp_graph(prefix, n, k, data, labels, max_num_threads):
  datadict = {'1 thread' if not i else '{0} threads'.format(i + 1):
              pd.Series(data[i], index=labels) for i in xrange(max_num_threads)}
  df = pd.DataFrame(datadict)

  plt.figure(figsize=(6, 6 * 3 / 4.0))
  ax = df.plot(marker='>', markersize=5, linewidth=2.5, legend=True)

  # title and labels
  ax.set_title('LowMC Timing n={0} k={1} - Parameters [m]-[r]'.format(n, k))
  ax.set_ylabel('Time [ms]')
  ax.set_xlabel('')

  ax.set_xticks(range(len(labels)))
  ax.set_xticklabels(labels, rotation=45, fontsize=8)

  # grid
  ax.grid(True, axis='y')

  plt.savefig('{0}-{1}-{2}.eps'.format(prefix, n, k))
  plt.savefig('{0}-{1}-{2}.png'.format(prefix, n, k))


def create_omp_graphs(n, k, prefix, max_num_threads):
  labels = None
  all_fis_sign = []
  all_fis_verify = []
  all_bg_sign = []
  all_bg_verify = []

  for threads in xrange(1, 1 + max_num_threads):
    with h5py.File('{0}-{1}-{2}-{3}.mat'.format(prefix, threads, n, k), 'r') as timings:
      if labels is None:
        labels = list(timings.get("labels"))[5:]

      fis_sum = np.array(timings.get("fis_sum"))
      bg_sum = np.array(timings.get("bg_sum"))

      all_fis_sign.append(compute_sign(fis_sum)[5:])
      all_fis_verify.append(compute_verify(fis_sum)[5:])
      all_bg_sign.append(compute_sign(bg_sum)[5:])
      all_bg_verify.append(compute_verify(bg_sum)[5:])

  create_omp_graph('{0}-fis-sign'.format(prefix), n, k, all_fis_sign, labels, max_num_threads)
  create_omp_graph('{0}-fis-verify'.format(prefix), n, k, all_fis_verify, labels, max_num_threads)
  create_omp_graph('{0}-bg-sign'.format(prefix), n, k, all_bg_sign, labels, max_num_threads)
  create_omp_graph('{0}-bg-verify'.format(prefix), n, k, all_bg_verify, labels, max_num_threads)


def main(args):
  sns.set(style='white', context='paper')
  sns.set_style('white', {'legend.frameon': True})

  n = args.blocksize
  k = args.keysize
  prefix = args.prefix

  if args.omp:
    return create_omp_graphs(n, k, prefix, args.threads)

  with h5py.File('{0}-{1}-{2}.mat'.format(prefix, n, k), 'r') as timings:
    labels = timings.get("labels")
    fis_sum = timings.get("fis_sum")
    bg_sum = timings.get("bg_sum")

    create_graph("{0}-fis".format(prefix), n, k, fis_sum, labels)
    create_graph("{0}-bg".format(prefix), n, k, bg_sum, labels)


if __name__ == "__main__":
  parser = argparse.ArgumentParser(description='Create graphs')
  parser.add_argument("-k", "--keysize", help="the LowMC keysize", type=int,
                      choices=[128, 192, 256, 384, 448, 512], default=128)
  parser.add_argument("-n", "--blocksize", help="the LowMC blocksize", type=int,
                      default=128)
  parser.add_argument("-p", "--prefix", help="prefix of mat files",
                      default="timings")
  parser.add_argument("-o", "--omp", help="produce graphs for omp runs",
                      action='store_true', default=False)
  parser.add_argument("-t", "--threads", help="# of OpenMP threads", type=int,
                      default=4)

  args = parser.parse_args()

  main(args)

