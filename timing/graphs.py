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


# from ZKBoo
mpc_sha256_proof = 187
mpc_sha256_verify = 89
mpc_sha256_size = 830

figsize=(10, 10 * 3 / 4.0)


def compute_size(data):
  return data[:, 12] / 1024


def compute_sign(data):
  return np.sum(data[:, 3:8] / 1000, axis=1)


def compute_verify(data):
  return np.sum(data[:, 8:12] / 1000, axis=1)


def round_up(x, f=5.0):
  return max(math.ceil(x / f) * f + f / 2.0, 0)


def round_down(x, f=5.0):
  return max(math.floor(x / f) * f - f / 2.0, 0)


def round_up_log(x):
  return round_up(2**(math.ceil(math.log(x, 2))), f=4.0)


def round_down_log(x):
  return round_down(x, 10.0)


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
    """
    indices = [j for (j, x) in enumerate(labels) if x.split('-')[1] == r]
    new_size.append(sum(size[j] for j in indices) / len(indices))
    new_sign.append(sum(sign[j] for j in indices) / len(indices))
    new_verify.append(sum(verify[j] for j in indices) / len(indices))
    """
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


class Annotation(object):
  def __init__(self, label, point, color, **style):
    self.label = label
    self.point = point
    self.style = {'horizontalalignment': 'left', 'xytext': (0,5), 'textcoords': 'offset points',
        'fontsize': 8}
    self.color = color

    if style is not None:
      self.style.update(style)

  def plot(self, ax):
    ax.plot([self.point[0]], [self.point[1]], marker='o', color=self.color, linestyle='',
            markersize=3)
    if self.label is not None:
      ax.annotate(self.label, xy=self.point, **self.style)


def create_graph(prefix, fis_n, bg_n, fis_k, bg_k, fis_data, bg_data, fis_labels, bg_labels):
  colors = sns.color_palette(n_colors=5)
  annotation_color = colors[0]

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

  fis_index = len(t_fis_labels) / 2 - 1
  bg_index = len(t_bg_labels) / 2 - 1

  annotate.append(Annotation(t_fis_labels[0],
                             (t_fis_size[0], t_fis_sign[0]),
                             annotation_color))
  annotate.append(Annotation(None,
                             (t_fis_size[0], t_fis_verify[0]),
                             annotation_color))
  annotate.append(Annotation(t_bg_labels[0],
                             (t_bg_size[0], t_bg_sign[0]),
                             annotation_color))
  annotate.append(Annotation(None,
                             (t_bg_size[0], t_bg_verify[0]),
                             annotation_color))

  annotate.append(Annotation(t_fis_labels[-1],
                             (t_fis_size[-1], t_fis_sign[-1]),
                             annotation_color))
  annotate.append(Annotation(None,
                             (t_fis_size[-1], t_fis_verify[-1]),
                             annotation_color))
  annotate.append(Annotation(t_bg_labels[-1],
                             (t_bg_size[-1], t_bg_sign[-1]),
                             annotation_color))
  annotate.append(Annotation(None,
                             (t_bg_size[-1], t_bg_verify[-1]),
                             annotation_color))

  annotate.append(Annotation(t_fis_labels[fis_index],
                             (t_fis_size[fis_index], t_fis_sign[fis_index]),
                             annotation_color))
  annotate.append(Annotation(None,
                             (t_fis_size[fis_index], t_fis_verify[fis_index]),
                             annotation_color))
  annotate.append(Annotation(t_bg_labels[bg_index],
                             (t_bg_size[bg_index], t_bg_sign[bg_index]),
                             annotation_color))
  annotate.append(Annotation(None,
                             (t_bg_size[bg_index], t_bg_verify[bg_index]),
                             annotation_color))

  annotate.append(Annotation('SHA256 proof',
                             (mpc_sha256_size, mpc_sha256_proof),
                             annotation_color, horizontalalignment='right'))
  annotate.append(Annotation('SHA256 verify',
                             (mpc_sha256_size, mpc_sha256_verify),
                             annotation_color, horizontalalignment='right'))

  combined_time = t_fis_sign + t_fis_verify + t_bg_sign + t_bg_verify + [mpc_sha256_proof,
      mpc_sha256_verify]
  combined_size = t_fis_size + t_bg_size + [mpc_sha256_size]

  ylim = (round_down_log(min(combined_time)), round_up_log(max(combined_time)))
  xlim = (round_down_log(min(combined_size)), round_up_log(max(combined_size)))

  df = pd.DataFrame(dataframes)
  df.sort_values(by=[k for k in dataframes.keys() if '_size_' in k], inplace=True)

  plt.figure(figsize=figsize)

  ax = None
  ax = df.plot(x='fis_size_{0}'.format(fis_n), y='fis_sign_{0}'.format(fis_n),
          label='Sign (FS) n={0}'.format(fis_n),
          ylim=ylim, xlim=xlim,
          color=colors[1], linestyle='--', ax=ax, logy=True, logx=True)
  df.plot(x='fis_size_{0}'.format(fis_n), y='fis_verify_{0}'.format(fis_n), label='Verify (FS) n={0}'.format(fis_n),
          ylim=ylim, xlim=xlim,
          ax=ax, color=colors[2], linestyle=':', logy=True, logx=True)
  df.plot(x='bg_size_{0}'.format(bg_n), y='bg_sign_{0}'.format(bg_n), label='Sign (BG) n={0}'.format(bg_n),
          ylim=ylim, xlim=xlim,
          color=colors[3], linestyle='--', ax=ax, logy=True, logx=True)
  df.plot(x='bg_size_{0}'.format(bg_n), y='bg_verify_{0}'.format(bg_n), label='Verify (BG) n={0}'.format(bg_n),
          ylim=ylim, xlim=xlim,
          ax=ax, color=colors[4], linestyle=':', logy=True, logx=True)

  for a in annotate:
    a.plot(ax)

  # title and labels
  ax.set_title('Runtime vs. Signature size, [n]-[k]-[m]-[r]'.format(k))
  ax.set_ylabel('Time [ms]')
  ax.set_xlabel('Size [kB]')

  # legend
  handles, labels = ax.get_legend_handles_labels()
  plt.legend(handles, labels, loc='upper center')

  # TODO: add better ticks!
  # TODO: fix xlim and ylim

  # grid
  # ax.yaxis.set_minor_locator(plticker.AutoMinorLocator(4))
  ax.grid(True, axis='y', which='both')

  plt.savefig('{0}.eps'.format(prefix))
  plt.savefig('{0}.png'.format(prefix))


def create_omp_graph(prefix, n, k, data, size, labels, max_num_threads, title=''):
  datadict = {'1 thread' if not i else '{0} threads'.format(i + 1):
              pd.Series(data[i], index=labels) for i in xrange(max_num_threads)}
  datadict['size'] = pd.Series(size, index=labels)

  df = pd.DataFrame(datadict)
  df.sort_values(by='size', inplace=True)

  plt.figure(figsize=figsize)

  colors = sns.color_palette(n_colors=max_num_threads)
  ax = None
  for i in xrange(max_num_threads):
    ax = df.plot(y='1 thread' if not i else '{0} threads'.format(i + 1), x='size', legend=True, ax=ax)

  # title and labels
  # ax.set_title('Parallel Execution with OpenMP {0}'.format(title))
  ax.set_ylabel('Time [ms]')
  ax.set_xlabel('Size [kB]')

  # grid
  ax.yaxis.set_minor_locator(plticker.AutoMinorLocator(4))
  ax.grid(True, axis='y', which='both')

  plt.savefig('{0}-{1}-{2}.eps'.format(prefix, n, k))
  plt.savefig('{0}-{1}-{2}.png'.format(prefix, n, k))


def create_omp_graphs(args):
  prefix = args.prefix
  n = args.bg_blocksize
  k = args.bg_keysize
  max_num_threads = args.threads

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

      fis_sum = np.array(timings.get("fis_mean"))
      bg_sum = np.array(timings.get("bg_mean"))

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

  create_omp_graph('{0}-fis-sign'.format(prefix), n, k, all_fis_sign, all_fis_size[0], labels,
      max_num_threads, title='(Sign)')
  create_omp_graph('{0}-fis-verify'.format(prefix), n, k, all_fis_verify, all_fis_size[0], labels,
      max_num_threads, title='(Verify)')
  create_omp_graph('{0}-bg-sign'.format(prefix), n, k, all_bg_sign, all_bg_size[0], labels,
      max_num_threads, title='(Sign)')
  create_omp_graph('{0}-bg-verify'.format(prefix), n, k, all_bg_verify, all_bg_size[0], labels,
      max_num_threads, title='(Verify)')


def create_graphs(args):
  prefix = args.prefix
  fis_n = args.fs_blocksize
  fis_k = args.fs_keysize
  bg_n = args.bg_blocksize
  bg_k = args.bg_keysize

  with h5py.File('{0}-{1}-{2}.mat'.format(prefix, fis_n, fis_k), 'r') as timings:
    fis_labels = list(timings.get("labels"))
    fis_sum = np.array(timings.get("fis_mean"))

  with h5py.File('{0}-{1}-{2}.mat'.format(prefix, bg_n, bg_k), 'r') as timings:
    bg_labels = list(timings.get("labels"))
    bg_sum = np.array(timings.get("bg_mean"))

  create_graph("{0}".format(prefix), fis_n, bg_n, fis_k, bg_k, fis_sum, bg_sum, fis_labels,
      bg_labels)


def create_qh_graphs(args):
  prefix = args.prefix
  bg_n = args.bg_blocksize
  bg_k = args.bg_keysize

  all_fis_sign = []
  all_fis_verify = []
  all_fis_label = []
  all_fis_size = []

  for n in args.fsblocksizes:
    with h5py.File('{0}-{1}-{2}.mat'.format(prefix, n, n), 'r') as timings:
      fis_labels = list(timings.get("labels"))
      fis_sum = np.array(timings.get("fis_mean"))

      size, sign, verify, label =  prepare_data(fis_sum, fis_labels)
      idx = len(label) / 2 - 1

      all_fis_sign.append(sign[idx])
      all_fis_size.append(size[idx])
      all_fis_verify.append(verify[idx])
      all_fis_label.append(label[idx])

  with h5py.File('{0}-{1}-{2}.mat'.format(prefix, bg_n, bg_k), 'r') as timings:
    bg_labels = list(timings.get("labels"))
    bg_sum = np.array(timings.get("bg_mean"))

    size, sign, verify, label = prepare_data(bg_sum, bg_labels)
    idx = len(label) / 2 - 1

    bg_size = size[idx]
    bg_verify = verify[idx]
    bg_sign = sign[idx]
    bg_label = label[idx]

  colors = sns.color_palette(n_colors=3)
  annotation_color = colors[0]

  dataframes = {}
  annotate = []

  dataframes['fis_sign'] = pd.Series(all_fis_sign, index=all_fis_label)
  dataframes['fis_verify'] = pd.Series(all_fis_verify, index=all_fis_label)
  dataframes['fis_size'] = pd.Series(all_fis_size, index=all_fis_label)

  df = pd.DataFrame(dataframes)
  df.sort_values(by=[k for k in dataframes.keys() if '_size' in k], inplace=True)

  annotate.append(Annotation('BG-{0}-{1}-{2} sign'.format(bg_n, bg_k, bg_label),
                             (bg_size, bg_sign),
                             annotation_color))
  annotate.append(Annotation('BG-{0}-{1}-{2} verify'.format(bg_n, bg_k, bg_label),
                             (bg_size, bg_verify),
                             annotation_color))


  plt.figure(figsize=figsize)

  ax = None
  ax = df.plot(x='fis_size', y='fis_sign',
          label='Sign (FS)',
          color=colors[1], linestyle='--', ax=ax)
  df.plot(x='fis_size', y='fis_verify', label='Verify (FS)',
          ax=ax, color=colors[2], linestyle=':')

  for a in annotate:
    a.plot(ax)

  # title and labels
  # ax.set_title('Runtime vs. Signature size with increasing q_H'.format(k))
  ax.set_ylabel('Time [ms]')
  ax.set_xlabel('Size [kB]')

  # legend
  handles, labels = ax.get_legend_handles_labels()
  plt.legend(handles, labels, loc='upper center')

  # TODO: add better ticks!
  # TODO: fix xlim and ylim

  # grid
  # ax.yaxis.set_minor_locator(plticker.AutoMinorLocator(4))
  ax.grid(True, axis='y', which='both')

  plt.savefig('qh-{0}.eps'.format(prefix))
  plt.savefig('qh-{0}.png'.format(prefix))


def main():
  sns.set(style='white', context='paper', color_codes=True)
  sns.set_style('white', {
    'legend.frameon': True,
    'font.family': ['serif'],
    'font.serif': ['Computer Modern Romand', 'serif']
  })

  parser = argparse.ArgumentParser(description='Create graphs')
  parser.add_argument("-p", "--prefix", help="prefix of mat files",
                      default="timings")
  subparsers = parser.add_subparsers()

  thread_parser = subparsers.add_parser('omp', help='OpenMP graphs')
  thread_parser.set_defaults(func=create_omp_graphs)
  thread_parser.add_argument("-t", "--threads", help="# of OpenMP threads", type=int, default=4)
  thread_parser.add_argument("--bg-keysize", help="LowMC key size for BG",
                             choices=[128, 192, 256, 384, 448, 512], required=True, type=int)
  thread_parser.add_argument("--bg-blocksize", help="LowMC block size for BG",
                             choices=[128, 192, 256, 384, 448, 512], required=True, type=int)

  default_parser = subparsers.add_parser('default', help='Size vs Runtime graphs')
  default_parser.set_defaults(func=create_graphs)
  default_parser.add_argument("--bg-keysize", help="LowMC key size for BG",
                      choices=[128, 192, 256, 384, 448, 512], required=True, type=int)
  default_parser.add_argument("--bg-blocksize", help="LowMC block size for BG",
                      choices=[128, 192, 256, 384, 448, 512], required=True, type=int)
  default_parser.add_argument("--fs-keysize", help="LowMC key size for FS",
                      choices=[128, 192, 256, 384, 448, 512], required=True, type=int)
  default_parser.add_argument("--fs-blocksize", help="LowMC block size for FS",
                      choices=[128, 192, 256, 384, 448, 512], required=True, type=int)

  qh_parser = subparsers.add_parser('qH', help='graphs for rising q_H')
  qh_parser.set_defaults(func=create_qh_graphs)
  qh_parser.add_argument("--bg-keysize", help="LowMC key size for BG",
                      choices=[128, 192, 256, 384, 448, 512], required=True, type=int)
  qh_parser.add_argument("--bg-blocksize", help="LowMC block size for BG",
                      choices=[128, 192, 256, 384, 448, 512], required=True, type=int)
  qh_parser.add_argument("fsblocksizes", help="LowMC block size for FS", type=int,
                      choices=[128, 192, 256, 384, 448, 512], nargs='+')

  args = parser.parse_args()
  args.func(args)


if __name__ == "__main__":
  main()

# vim: tw=100 sts=2 sw=2 et
