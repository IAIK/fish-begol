import argparse
import h5py
import numpy as np
import matplotlib
import matplotlib.ticker as plticker
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
import math
from operator import itemgetter


def compute_size(data):
  return data[:, 12] / 1024


def compute_sign(data):
  return np.sum(data[:, 3:8] / 1000, axis=1)


def compute_verify(data):
  return np.sum(data[:, 8:12] / 1000, axis=1)


def round_up(x):
  return math.ceil(x / 10.0) * 10 + 5


def round_down(x):
  return max(math.floor(x / 10.0) * 10 - 5, 0)


def pick_5(size, sign, verify, labels):
  if len(labels) <= 5:
    return size, sign, verify, labels

  # always remove first and last one
  del size[-1]
  del sign[-1]
  del verify[-1]
  del labels[-1]
  del size[0]
  del sign[0]
  del verify[0]
  del labels[0]

  if len(labels) <= 5:
    return size, sign, verify, labels

  l = len(labels)
  s = len(labels) / 5

  return size[0:l:s], sign[0:l:s], verify[0:l:s], labels[0:l:s]


def pick_interesting(size, sign, verify, labels):
  new_size = []
  new_sign = []
  new_verify = []
  new_labels = []
  rounds = set()

  for i in range(len(labels)):
    m, r = labels[i].split('-')
    if r in rounds:
      continue

    rounds.add(r)
    new_size.append(size[i])
    new_sign.append(sign[i])
    new_verify.append(verify[i])
    new_labels.append(labels[i])

  return new_size, new_sign, new_verify, new_labels


def prepare_data(data, labels):
  size = data[:, 3]
  sign = data[:, 1]
  verify = data[:, 2]
  return pick_interesting(size, sign, verify, labels)


def create_graph(prefix, fis_n, bg_n, fis_k, bg_k, fis_data, bg_data, fis_labels, bg_labels):
  dataframes = {}
  annotate = []

  t_fis_size, t_fis_sign, t_fis_verify, t_fis_labels = prepare_data(fis_data, fis_labels)
  t_bg_size, t_bg_sign, t_bg_verify, t_bg_labels = prepare_data(bg_data, bg_labels)

  t_fis_labels = ["{0}-{1}-{2}".format(fis_n, fis_k, l) for l in t_fis_labels]
  t_bg_labels = ["{0}-{1}-{2}".format(bg_n, bg_k, l) for l in t_bg_labels]

  dataframes['fis_sign_{0}'.format(fis_n)] = pd.Series(t_fis_sign, index=t_fis_labels)
  dataframes['fis_verify_{0}'.format(fis_n)] = pd.Series(t_fis_verify, index=t_fis_labels)
  dataframes['fis_size_{0}'.format(fis_n)] = pd.Series(t_fis_size, index=t_fis_labels)
  dataframes['bg_sign_{0}'.format(bg_n)] = pd.Series(t_bg_sign, index=t_bg_labels)
  dataframes['bg_verify_{0}'.format(bg_n)] = pd.Series(t_bg_verify, index=t_bg_labels)
  dataframes['bg_size_{0}'.format(bg_n)] = pd.Series(t_bg_size, index=t_bg_labels)

  fis_index = len(t_fis_labels) / 2
  bg_index = len(t_bg_labels) / 2

  annotate.append((t_fis_labels[fis_index], (t_fis_size[fis_index], t_fis_sign[fis_index]),
    (t_fis_size[fis_index], t_fis_verify[fis_index])))
  annotate.append((t_bg_labels[bg_index], (t_bg_size[bg_index], t_bg_sign[bg_index]),
    (t_bg_size[bg_index], t_bg_verify[bg_index])))

  ylim = (round_down(min(t_fis_sign + t_fis_verify + t_bg_sign + t_bg_verify)), round_up(max(t_fis_sign + t_fis_verify + t_bg_sign + t_bg_verify)))
  xlim = (round_down(min(t_fis_size + t_bg_size)), round_up(max(t_fis_size + t_bg_size)))

  df = pd.DataFrame(dataframes)
  df.sort_values(by=[k for k in dataframes.keys() if '_size_' in k], inplace=True)

  plt.figure(figsize=(10, 10 * 3 / 4.0))

  colors = sns.color_palette(n_colors=5)
  annotation_color = colors[0]

  ax = None
  ax = df.plot(x='fis_size_{0}'.format(fis_n), y='fis_sign_{0}'.format(fis_n),
          label='Sign (FS) n={0}'.format(fis_n), ylim=ylim, xlim=xlim,
          color=colors[1], linestyle='--', ax=ax)
  df.plot(x='fis_size_{0}'.format(fis_n), y='fis_verify_{0}'.format(fis_n), label='Verify (FS) n={0}'.format(fis_n), ylim=ylim, xlim=xlim,
          ax=ax, color=colors[2], linestyle=':')
  df.plot(x='bg_size_{0}'.format(bg_n), y='bg_sign_{0}'.format(bg_n), label='Sign (BG) n={0}'.format(bg_n), ylim=ylim, xlim=xlim,
          color=colors[3], linestyle='--', ax=ax)
  df.plot(x='bg_size_{0}'.format(bg_n), y='bg_verify_{0}'.format(bg_n), label='Verify (BG) n={0}'.format(bg_n), ylim=ylim, xlim=xlim,
          ax=ax, color=colors[4], linestyle=':')

  for (label, p1, p2) in annotate:
    ax.plot([p1[0], p2[0]], [p1[1], p2[1]], marker='o', color=annotation_color, linestyle='',
            markersize=3)
    ax.annotate(label, xy=p1, textcoords='offset points', xytext=(0,5), fontsize=8,
                horizontalalignment='center')

  # title and labels
  ax.set_title('Runtime vs. Signature size, [n]-[k]-[m]-[r]'.format(k))
  ax.set_ylabel('Time [ms]')
  ax.set_xlabel('Size [kB]')

  # grid
  ax.yaxis.set_minor_locator(plticker.AutoMinorLocator(4))
  ax.grid(True, axis='y', which='both')

  plt.savefig('{0}.eps'.format(prefix))
  plt.savefig('{0}.png'.format(prefix))


def create_omp_graph(prefix, n, k, data, size, labels, max_num_threads):
  datadict = {'1 thread' if not i else '{0} threads'.format(i + 1):
              pd.Series(data[i], index=labels) for i in xrange(max_num_threads)}
  datadict['size'] = pd.Series(size, index=labels)

  df = pd.DataFrame(datadict)
  df.sort_values(by='size', inplace=True)

  plt.figure(figsize=(10, 10 * 3 / 4.0))

  colors = sns.color_palette(n_colors=max_num_threads)
  ax = None
  for i in xrange(max_num_threads):
    ax = df.plot(y='1 thread' if not i else '{0} threads'.format(i + 1), x='size', legend=True, ax=ax)

  # title and labels
  ax.set_title('Parallel Execution'.format(n, k))
  ax.set_ylabel('Time [ms]')
  ax.set_xlabel('Size [kB]')

  # grid
  ax.yaxis.set_minor_locator(plticker.AutoMinorLocator(4))
  ax.grid(True, axis='y', which='both')

  plt.savefig('{0}-{1}-{2}.eps'.format(prefix, n, k))
  plt.savefig('{0}-{1}-{2}.png'.format(prefix, n, k))


def create_omp_graphs(n, k, prefix, max_num_threads):
  labels = None
  all_fis_sign = []
  all_fis_verify = []
  all_bg_sign = []
  all_bg_verify = []
  all_fis_size = []
  all_bg_size = []

  for threads in range(1, 1 + max_num_threads):
    with h5py.File('{0}-{1}-{2}-{3}.mat'.format(prefix, threads, n, k), 'r') as timings:
      ol = list(timings.get("labels"))

      fis_sum = np.array(timings.get("fis_median"))
      bg_sum = np.array(timings.get("bg_median"))

      size, sign, verify, l =  prepare_data(fis_sum[2:], ol[2:])
      all_fis_sign.append(sign)
      all_fis_verify.append(verify)
      all_fis_size.append(size)

      size, sign, verify, l =  prepare_data(bg_sum[2:], ol[2:])
      all_bg_sign.append(sign)
      all_bg_verify.append(verify)
      all_bg_size.append(size)

      if labels is None:
        labels = l

  create_omp_graph('{0}-fis-sign'.format(prefix), n, k, all_fis_sign, all_fis_size[0], labels, max_num_threads)
  create_omp_graph('{0}-fis-verify'.format(prefix), n, k, all_fis_verify, all_fis_size[0], labels, max_num_threads)
  create_omp_graph('{0}-bg-sign'.format(prefix), n, k, all_bg_sign, all_bg_size[0], labels, max_num_threads)
  create_omp_graph('{0}-bg-verify'.format(prefix), n, k, all_bg_verify, all_bg_size[0], labels, max_num_threads)


def main(args):
  sns.set(style='white', context='paper', color_codes=True)
  sns.set_style('white', {'legend.frameon': True})

  prefix = args.prefix

  if args.omp:
    n = args.bg_blocksize
    k = args.bg_keysize
    return create_omp_graphs(n, k, prefix, args.threads)

  fis_n = args.fs_blocksize
  fis_k = args.fs_keysize
  bg_n = args.bg_blocksize
  bg_k = args.bg_keysize

  with h5py.File('{0}-{1}-{2}.mat'.format(prefix, fis_n, fis_k), 'r') as timings:
    fis_labels = list(timings.get("labels"))
    fis_sum = np.array(timings.get("fis_median"))

  with h5py.File('{0}-{1}-{2}.mat'.format(prefix, bg_n, bg_k), 'r') as timings:
    bg_labels = list(timings.get("labels"))
    bg_sum = np.array(timings.get("bg_median"))

  create_graph("{0}".format(prefix), fis_n, bg_n, fis_k, bg_k, fis_sum, bg_sum, fis_labels,
      bg_labels)


if __name__ == "__main__":
  parser = argparse.ArgumentParser(description='Create graphs')
  parser.add_argument("--bg-keysize", help="LowMC key size for BG",
                      choices=[128, 192, 256, 384, 448, 512], required=True, type=int)
  parser.add_argument("--fs-keysize", help="LowMC key size for FS",
                      choices=[128, 192, 256, 384, 448, 512], required=True, type=int)
  parser.add_argument("--bg-blocksize", help="LowMC key size for BG",
                      choices=[128, 192, 256, 384, 448, 512], required=True, type=int)
  parser.add_argument("--fs-blocksize", help="LowMC key size for FS",
                      choices=[128, 192, 256, 384, 448, 512], required=True, type=int)
  parser.add_argument("-p", "--prefix", help="prefix of mat files",
                      default="timings")
  parser.add_argument("-o", "--omp", help="produce graphs for omp runs",
                      action='store_true', default=False)
  parser.add_argument("-t", "--threads", help="# of OpenMP threads", type=int,
                      default=4)

  args = parser.parse_args()

  main(args)

# vim: tw=100 sts=2 sw=2 et
