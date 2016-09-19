import argparse
import h5py
import numpy as np
import matplotlib
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
import math


def compute_size(data):
  return data[:, 12] / 1024


def compute_sign(data):
  return np.sum(data[:, 3:7] / 1000, axis=1)


def compute_verify(data):
  return np.sum(data[:, 8:12] / 1000, axis=1)


def round_up(x):
  return math.ceil(x / 10.0) * 10 + 5


def round_down(x):
  return math.floor(x / 10.0) * 10 - 5


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

  return pick_5(new_size, new_sign, new_verify, new_labels)


def prepare_data(data, labels):
  size = compute_size(data)
  sign = compute_sign(data)
  verify = compute_verify(data)
  return pick_interesting(size, sign, verify, labels)


def create_graph(prefix, ns, k, fis_data, bg_data, labels):
  fis_size = []
  fis_sign = []
  fis_verify = []
  fis_labels = []
  bg_size = []
  bg_sign = []
  bg_verify = []
  bg_labels = []

  dataframes = {}
  annotate = {}

  for i in range(len(ns)):
    n = ns[i]
    t_fis_size, t_fis_sign, t_fis_verify, t_fis_labels = prepare_data(fis_data[i], labels[i])
    t_bg_size, t_bg_sign, t_bg_verify, t_bg_labels = prepare_data(bg_data[i], labels[i])

    t_fis_labels = ["{0}-{1}-{2}".format(n, k, l) for l in t_fis_labels]
    t_bg_labels = ["{0}-{1}-{2}".format(n, k, l) for l in t_bg_labels]

    dataframes['fis_sign_{0}'.format(n)] = pd.Series(t_fis_sign, index=t_fis_labels)
    dataframes['fis_verify_{0}'.format(n)] = pd.Series(t_fis_verify, index=t_fis_labels)
    dataframes['fis_size_{0}'.format(n)] = pd.Series(t_fis_size, index=t_fis_labels)
    dataframes['bg_sign_{0}'.format(n)] = pd.Series(t_bg_sign, index=t_bg_labels)
    dataframes['bg_verify_{0}'.format(n)] = pd.Series(t_bg_verify, index=t_bg_labels)
    dataframes['bg_size_{0}'.format(n)] = pd.Series(t_bg_size, index=t_bg_labels)

    annotate[t_fis_labels[2]] = ((t_fis_size[2], max(t_fis_sign[2],
        t_fis_verify[2])), (t_bg_size[2], max(t_bg_sign[2], t_bg_verify[2])))

    fis_size.extend(t_fis_size)
    fis_sign.extend(t_fis_sign)
    fis_verify.extend(t_fis_verify)
    bg_size.extend(t_bg_size)
    bg_sign.extend(t_bg_sign)
    bg_verify.extend(t_bg_verify)

  ylim = (0, round_up(max(fis_sign + fis_verify + bg_sign + bg_verify)))
  xlim = (round_down(min(fis_size + bg_size)), round_up(max(fis_size + bg_size)))

  df = pd.DataFrame(dataframes)

  plt.figure(figsize=(10, 10 * 3 / 4.0))

  colors = sns.color_palette(n_colors=len(ns) * 2)
  i = 0
  ax = None
  for n in ns:
    ax = df.plot.scatter(x='fis_size_{0}'.format(n), y='fis_sign_{0}'.format(n),
            label='Sign (FS) n={0}'.format(n), ylim=ylim, xlim=xlim,
            color=colors[i], marker='*', ax=ax)
    df.plot.scatter(x='fis_size_{0}'.format(n), y='fis_verify_{0}'.format(n), label='Verify (FS) n={0}'.format(n), ylim=ylim, xlim=xlim,
                    ax=ax, color=colors[i], marker='.')
    df.plot.scatter(x='bg_size_{0}'.format(n), y='bg_sign_{0}'.format(n), label='Sign (BG) n={0}'.format(n), ylim=ylim, xlim=xlim,
            color=colors[i + 1], marker='*', ax=ax)
    df.plot.scatter(x='bg_size_{0}'.format(n), y='bg_verify_{0}'.format(n), label='Verify (BG) n={0}'.format(n), ylim=ylim, xlim=xlim,
                    ax=ax, color=colors[i + 1], marker='.')
    i += 2

  def annotate_df(row):
    arrow = {'facecolor': 'r', 'connectionstyle': 'arc3', 'arrowstyle': '->',
             'shrinkB': 5, 'shrinkA': 10}

    if row.name in annotate:
      ax.annotate(row.name, xy=annotate[row.name][0],
              xytext=(annotate[row.name][0][0], ylim[1] - 20), fontsize=5,
              arrowprops=arrow)
      ax.annotate(row.name, xy=annotate[row.name][1],
              xytext=(annotate[row.name][0][0], ylim[1] - 20), fontsize=5,
              arrowprops=arrow)

  df.apply(annotate_df, axis=1)

  # title and labels
  ax.set_title('Signature Scheme Timing')
  ax.set_ylabel('Time [ms]')
  ax.set_xlabel('Size [kB]')

  # grid
  ax.grid(True, axis='y')

  plt.savefig('{0}.eps'.format(prefix))
  plt.savefig('{0}.png'.format(prefix))


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

  for threads in range(1, 1 + max_num_threads):
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
  sns.set(style='white', context='paper', color_codes=True)
  sns.set_style('white', {'legend.frameon': True})

  k = args.keysize
  prefix = args.prefix

  if args.omp:
    n = args.blocksize[0]
    return create_omp_graphs(n, k, prefix, args.threads)

  all_labels = []
  all_fis_sums = []
  all_bg_sums = []

  for n in args.blocksize:
    with h5py.File('{0}-{1}-{2}.mat'.format(prefix, n, k), 'r') as timings:
      labels = list(timings.get("labels"))
      fis_sum = np.array(timings.get("fis_sum"))
      bg_sum = np.array(timings.get("bg_sum"))

      all_labels.append(labels)
      all_fis_sums.append(fis_sum)
      all_bg_sums.append(bg_sum)

  create_graph("{0}".format(prefix), args.blocksize, k, all_fis_sums,
               all_bg_sums, all_labels)


if __name__ == "__main__":
  parser = argparse.ArgumentParser(description='Create graphs')
  parser.add_argument("-k", "--keysize", help="the LowMC keysize", type=int,
                      choices=[128, 192, 256, 384, 448, 512], default=128)
  parser.add_argument("blocksize", help="the LowMC blocksize", type=int,
                      nargs='+')
  parser.add_argument("-p", "--prefix", help="prefix of mat files",
                      default="timings")
  parser.add_argument("-o", "--omp", help="produce graphs for omp runs",
                      action='store_true', default=False)
  parser.add_argument("-t", "--threads", help="# of OpenMP threads", type=int,
                      default=4)

  args = parser.parse_args()

  main(args)

