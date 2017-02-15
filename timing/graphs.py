#!/usr/bin/python3

# fish-begol - Implementation of the Fish and Begol signature schemes
# Copyright (C) 2016 Graz University of Technology
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

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
import json
import os.path


# from ZKBoo (SHA-256, 219 rounds)
mpc_sha256_proof = 187
mpc_sha256_verify = 89
mpc_sha256_size = 1368312 / 1024.0

figsize=(10, 10 * 3 / 4.0)

strings = {
  'FS': '${\sf Fish}$',
  'BG': '${\sf Begol}$',
  'Verify': '${\sf Verify}$',
  'Sign': '${\sf Sign}$'
}

class ScalarFormatterLim(plticker.ScalarFormatter):

  def __init__(self, minval, maxval, base, *args, **kwargs):
    self.minval = minval
    self.maxval = maxval
    self.base = base
    super(ScalarFormatterLim, self).__init__(*args, **kwargs)

  def pprint_val(self, value):
    if (value >= self.minval and value < self.maxval) or int(value) % self.base == 0:
      return super(ScalarFormatterLim, self).pprint_val(value)
    return ''


class MultiScalarFormatterLim(plticker.ScalarFormatter):

  def __init__(self, minvals, maxvals, bases, *args, **kwargs):
    self.minval = minvals
    self.maxval = maxvals
    self.base = bases
    self.len = len(bases)

    assert len(minvals) == len(maxvals) == len(bases)

    super(MultiScalarFormatterLim, self).__init__(*args, **kwargs)

  def pprint_val(self, value):
    for i in range(self.len):
      if (value >= self.minval[i] and value < self.maxval[i]) and int(value) % self.base[i] == 0:
        return super(MultiScalarFormatterLim, self).pprint_val(value)
    return ''


def lookup_style(style, *args):
  for a in args:
    if a in style:
      style = style[a]
    else:
      return {}
  return style


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
            markersize=4)
    if self.label is not None:
      ax.annotate(self.label, xy=self.point, **self.style)


def create_graph(prefix, fis_n, bg_n, fis_k, bg_k, fis_data, bg_data, fis_labels, bg_labels,
                 fis_annotate=None, bg_annotate=None, include_sha=True, style={}, **kwargs):
  colors = sns.color_palette('Greys_d', n_colors=5)
  annotation_color = colors[0]
  annotation_color_e = 'r'
  annotation_color_b = 'g'

  dataframes = {}
  annotate = []

  t_fis_size, t_fis_sign, t_fis_verify, t_fis_labels = prepare_data(fis_data, fis_labels)
  if bg_data is not None:
    t_bg_size, t_bg_sign, t_bg_verify, t_bg_labels = prepare_data(bg_data, bg_labels)

  if fis_annotate is not None:
    fis_index = t_fis_labels.index(fis_annotate)
  else:
    fis_index = len(t_fis_labels) // 2

  if bg_data is not None:
    if bg_annotate is not None:
      bg_index = t_bg_labels.index(bg_annotate)
    else:
      bg_index = len(t_bg_labels) // 2

  t_fis_labels = ['{0}-{1}-{2}'.format(fis_n, fis_k, l) for l in t_fis_labels]
  if bg_data is not None:
    t_bg_labels = ['{0}-{1}-{2}'.format(bg_n, bg_k, l) for l in t_bg_labels]

  dataframes['fis_sign_{0}'.format(fis_n)] = pd.Series(t_fis_sign, index=t_fis_labels)
  dataframes['fis_verify_{0}'.format(fis_n)] = pd.Series(t_fis_verify, index=t_fis_labels)
  dataframes['fis_size_{0}'.format(fis_n)] = pd.Series(t_fis_size, index=t_fis_labels)
  if bg_data is not None:
    dataframes['bg_sign_{0}'.format(bg_n)] = pd.Series(t_bg_sign, index=t_bg_labels)
    dataframes['bg_verify_{0}'.format(bg_n)] = pd.Series(t_bg_verify, index=t_bg_labels)
    dataframes['bg_size_{0}'.format(bg_n)] = pd.Series(t_bg_size, index=t_bg_labels)

  fis_min_index = t_fis_size.index(min(t_fis_size))
  fis_max_index = t_fis_size.index(max(t_fis_size))
  if bg_data is not None:
    bg_min_index = t_bg_size.index(min(t_bg_size))
    bg_max_index = t_bg_size.index(max(t_bg_size))


  def annotate_and_print(scheme, labels, size, sign, verify, index, color=annotation_color_e):
    annotate.append(Annotation(labels[index], (size[index], sign[index]), color))
    annotate.append(Annotation(None, (size[index], verify[index]), color))
    print("Annotating {} {}: size={}, sign={}, verify={}".format(scheme, labels[index],
        size[index] * 1024, sign[index], verify[index]))

  annotate_and_print("Fish", t_fis_labels, t_fis_size, t_fis_sign, t_fis_verify, fis_min_index)
  annotate_and_print("Fish", t_fis_labels, t_fis_size, t_fis_sign, t_fis_verify, fis_max_index)
  annotate_and_print("Fish", t_fis_labels, t_fis_size, t_fis_sign, t_fis_verify, fis_index,
      color=annotation_color_b)

  if bg_data is not None:
    annotate_and_print("Begol", t_bg_labels, t_bg_size, t_bg_sign, t_bg_verify, bg_min_index)
    annotate_and_print("Begol", t_bg_labels, t_bg_size, t_bg_sign, t_bg_verify, bg_max_index)
    annotate_and_print("Begol", t_bg_labels, t_bg_size, t_bg_sign, t_bg_verify, bg_index,
        color=annotation_color_b)

  combined_time = t_fis_sign + t_fis_verify
  combined_size = t_fis_size
  if bg_data is not None:
    combined_time += t_bg_sign + t_bg_verify
    combined_size += t_bg_size

  if include_sha and 'sha_proof' in kwargs and 'sha_verify' in kwargs and 'sha_size' in kwargs:
    sha_proof = kwargs['sha_proof']
    sha_verify = kwargs['sha_verify']
    sha_size = kwargs['sha_size']

    annotate.append(Annotation('SHA256 proof',
                               (sha_size, sha_proof),
                               annotation_color, horizontalalignment='right'))
    annotate.append(Annotation('SHA256 verify',
                               (sha_size, sha_verify),
                               annotation_color, horizontalalignment='right'))

    combined_time += [sha_proof, sha_verify]
    combined_size += [sha_size]

  ylim = (0, round_up_log(max(combined_time)))
  xlim = (round_down_log(min(combined_size)), round_up_log(max(combined_size)))

  df = pd.DataFrame(dataframes)
  df.sort_values(by=[k for k in dataframes.keys() if '_size_' in k], inplace=True)

  plt.figure(figsize=figsize)

  args = {'logy': True, 'logx': True, 'linewidth': 1, 'ax': None}
  args['ax'] = df.plot(x='fis_size_{0}'.format(fis_n), y='fis_sign_{0}'.format(fis_n),
          label=('{Sign} ({FS})' + (' n={0}' if bg_n != fis_n else '')).format(fis_n, **strings),
          color=colors[-1], linestyle='--', **args)
  df.plot(x='fis_size_{0}'.format(fis_n), y='fis_verify_{0}'.format(fis_n),
          label=('{Verify} ({FS})' + (' n={0}' if bg_n != fis_n else '')).format(fis_n, **strings),
          color=colors[-1], linestyle=':', **args)
  if bg_data is not None:
    df.plot(x='bg_size_{0}'.format(bg_n), y='bg_sign_{0}'.format(bg_n),
            label=('{Sign} ({BG})'  + (' n={0}' if bg_n != fis_n else '')).format(bg_n, **strings),
            color=colors[0], linestyle='--', **args)
    df.plot(x='bg_size_{0}'.format(bg_n), y='bg_verify_{0}'.format(bg_n),
            label=('{Verify} ({BG})'  + (' n={0}' if bg_n != fis_n else '')).format(bg_n, **strings),
            color=colors[0], linestyle=':', **args)

  ax = args['ax']
  for a in annotate:
    a.plot(ax)

  # title and labels
  ax.set_title('Runtime vs. Signature Size, [n]-[k]-[m]-[r]' + (', n={0}'.format(bg_n) if bg_n == fis_n else ''))
  ax.set_ylabel('Time [ms]')
  ax.set_xlabel('Size [kB]')

  # legend
  handles, labels = ax.get_legend_handles_labels()
  plt.legend(handles, labels, loc='lower right', prop=lookup_style(style, 'legend', 'n={0}'.format(bg_n)))

  # limits
  ax.set_xlim(xlim)
  ax.set_ylim(ylim)

  # grid and ticks
  ax.xaxis.set_major_locator(plticker.MultipleLocator(50))
  ax.yaxis.set_major_locator(plticker.MultipleLocator(10 if bg_n == 128 else 50))
  ax.xaxis.set_major_formatter(MultiScalarFormatterLim([0, 200, 600, 1000], [200, 600, 1000, 10000],
    [50, 100, 200, 500]))
  if bg_n == 128:
    ax.yaxis.set_major_formatter(ScalarFormatterLim(0, 50, 100))
  else:
    ax.yaxis.set_major_formatter(MultiScalarFormatterLim([0, 200, 600, 1000], [200, 600, 1000, 10000],
    [50, 100, 200, 500]))

  ax.grid(True, axis='y', which='both')

  plt.savefig('{0}.eps'.format(prefix))
  plt.savefig('{0}.pdf'.format(prefix))


def create_omp_graph(prefix, n, k, data, size, labels, max_num_threads, title=''):
  datadict = {'1 thread' if not i else '{0} threads'.format(i + 1):
              pd.Series(data[i], index=labels) for i in range(max_num_threads)}
  datadict['size'] = pd.Series(size, index=labels)

  df = pd.DataFrame(datadict)
  df.sort_values(by='size', inplace=True)

  plt.figure(figsize=figsize)

  colors = sns.color_palette(n_colors=max_num_threads)
  ax = None
  for i in range(max_num_threads):
    ax = df.plot(y='1 thread' if not i else '{0} threads'.format(i + 1), x='size', legend=True, ax=ax)

  # title and labels
  # ax.set_title('Parallel Execution with OpenMP {0}'.format(title))
  ax.set_ylabel('Time [ms]')
  ax.set_xlabel('Size [kB]')

  # grid
  ax.yaxis.set_minor_locator(plticker.AutoMinorLocator(4))
  ax.grid(True, axis='y', which='both')

  plt.savefig('{0}-{1}-{2}.eps'.format(prefix, n, k))
  plt.savefig('{0}-{1}-{2}.pdf'.format(prefix, n, k))


def fix_h5py_strings(strings):
  def f(s):
    if isinstance(s, bytes):
      return s.decode('utf-8')
    else:
      return s

  return [f(s) for s in strings]


def create_omp_graphs(args, style=None):
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
      ol = fix_h5py_strings(list(timings.get('labels')))

      fis_sum = np.array(timings.get('fis_mean'))
      if timings.get('bg_mean') is not None:
        bg_sum = np.array(timings.get('bg_mean'))
      else:
        bg_sum = None

      size, sign, verify, l =  prepare_data(fis_sum[2:], ol[2:])
      all_fis_sign.append(sign)
      all_fis_verify.append(verify)
      all_fis_size.append(size)

      if bg_sum is not None:
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
  if len(all_bg_sign):
    create_omp_graph('{0}-bg-sign'.format(prefix), n, k, all_bg_sign, all_bg_size[0], labels,
        max_num_threads, title='(Sign)')
    create_omp_graph('{0}-bg-verify'.format(prefix), n, k, all_bg_verify, all_bg_size[0], labels,
        max_num_threads, title='(Verify)')


def create_graphs(args, style=None):
  prefix = args.prefix
  fis_n = args.fs_blocksize
  fis_k = args.fs_keysize
  bg_n = args.bg_blocksize
  bg_k = args.bg_keysize

  with h5py.File('{0}-{1}-{2}.mat'.format(prefix, fis_n, fis_k), 'r') as timings:
    fis_labels = fix_h5py_strings(list(timings.get('labels')))
    fis_sum = np.array(timings.get('fis_mean'))

  if os.path.exists('{0}-{1}-{2}.mat'.format(prefix, bg_n, bg_k)):
    with h5py.File('{0}-{1}-{2}.mat'.format(prefix, bg_n, bg_k), 'r') as timings:
      if timings.get('bg_mean') is not None:
        bg_labels = fix_h5py_strings(list(timings.get('labels')))
        bg_sum = np.array(timings.get('bg_mean'))
      else:
        bg_labels = None
        bg_sum = None

  create_graph('{0}'.format(prefix), fis_n, bg_n, fis_k, bg_k, fis_sum, bg_sum, fis_labels,
      bg_labels, args.fs_annotate, args.bg_annotate, style=style, sha_size=args.sha_size,
      sha_verify=args.sha_verify, sha_proof=args.sha_proof)


def create_qh_graphs(args, style=None):
  prefix = args.prefix
  bg_n = args.bg_blocksize
  bg_k = args.bg_keysize

  dataframes = {}
  annotate = []

  with h5py.File('{0}-{1}-{2}.mat'.format(prefix, bg_n, bg_k), 'r') as timings:
    bg_labels = fix_h5py_strings(list(timings.get('labels')))
    bg_sum = np.array(timings.get('bg_mean'))

    bg_size, bg_sign, bg_verify, bg_label = prepare_data(bg_sum, bg_labels)
    dataframes['bg_sign'] = pd.Series(bg_sign, index=bg_label)
    dataframes['bg_verify'] = pd.Series(bg_verify, index=bg_label)
    dataframes['bg_size'] = pd.Series(bg_size, index=bg_label)

    min_idx = bg_size.index(min(bg_size))
    max_idx = bg_size.index(max(bg_size))

    xlim = [min(bg_size), max(bg_size)]
    ylim = [0, max(bg_sign)]

    if args.annotate_extreme:
      min_label = '{0}-{1}-{2}'.format(bg_n, bg_k, bg_label[min_idx])
      min_style = lookup_style(style, 'omp', 'BG', min_label)
      max_label = '{0}-{1}-{2}'.format(bg_n, bg_k, bg_label[max_idx])
      max_style = lookup_style(style, 'omp', 'BG', max_label)

      annotate.append(Annotation(min_label,
                                 (bg_size[min_idx], bg_sign[min_idx]), 'r', **min_style))
      annotate.append(Annotation(max_label,
                                 (bg_size[max_idx], bg_sign[max_idx]), 'r', **max_style))

    if args.bg_annotate:
      try:
        idx = bg_label.index(args.bg_annotate)

        alabel = '{0}-{1}-{2}'.format(bg_n, bg_k, bg_label[idx])
        astyle = lookup_style(style, 'omp', 'BG', alabel)

        annotate.append(Annotation(alabel,
                                   (bg_size[idx], bg_sign[idx]), 'g', **astyle))
      except ValueError:
        pass

  fs_annotations = args.fs_annotate.split(' ')
  for n in args.fsblocksizes:
    with h5py.File('{0}-{1}-{2}.mat'.format(prefix, n, n), 'r') as timings:
      fis_labels = fix_h5py_strings(list(timings.get('labels')))
      fis_sum = np.array(timings.get('fis_mean'))

      size, sign, verify, label =  prepare_data(fis_sum, fis_labels)

      dataframes['fis_sign_{0}'.format(n)] = pd.Series(sign, index=label)
      dataframes['fis_verify_{0}'.format(n)] = pd.Series(verify, index=label)
      dataframes['fis_size_{0}'.format(n)] = pd.Series(size, index=label)

      min_idx = size.index(min(size))
      max_idx = size.index(max(size))

      xlim = [min(size + xlim), max(size + xlim)]
      ylim = [0, max(sign + ylim)]

      if args.annotate_extreme:
        min_label = '{0}-{1}-{2}'.format(n, n, label[min_idx])
        min_style = lookup_style(style, 'omp', 'FS', min_label)
        max_label = '{0}-{1}-{2}'.format(n, n, label[max_idx])
        max_style = lookup_style(style, 'omp', 'FS', max_label)

        annotate.append(Annotation(min_label,
                                   (size[min_idx], sign[min_idx]), 'r', **min_style))
        annotate.append(Annotation(max_label,
                                   (size[max_idx], sign[max_idx]), 'r', **max_style))

      if args.fs_annotate:
        idx = None
        try:
          for annot in fs_annotations:
            if annot.startswith('{0}-{0}'.format(n)):
              idx = label.index('-'.join(annot.split('-')[2:]))
        except ValueError:
          pass

        if idx is not None:
          alabel = '{0}-{1}-{2}'.format(n, n, label[idx])
          astyle = lookup_style(style, 'omp', 'FS', alabel)

          annotate.append(Annotation(alabel,
                                     (size[idx], sign[idx]), 'g', **astyle))


  xlim = (round_down_log(xlim[0]), round_up_log(xlim[1]))
  ylim = (0, round_up_log(ylim[1]))

  colors = sns.color_palette('Greys_d', n_colors=len(args.fsblocksizes) + 1)
  annotation_color = 'g'

  df = pd.DataFrame(dataframes)
  df.sort_values(by=[k for k in dataframes.keys() if '_size' in k], inplace=True)

  plt.figure(figsize=figsize)

  pargs = {'xlim': xlim, 'ylim': ylim, 'logx': True, 'logy': True, 'ax': None}
  pargs['ax'] = df.plot(x='bg_size', y='bg_sign', label='{BG}, $Q_H = 2^{{60}}, \ldots, 2^{{100}}$'.format(**strings), color=colors[0], linestyle='-',
                        **pargs)

  qhs = [60, 80, 100, 120]
  linestyles = ['-.', ':', '--']
  for i in range(len(args.fsblocksizes)):
    n = args.fsblocksizes[i]
    qh = qhs[i]
    df.plot(x='fis_size_{0}'.format(n), y='fis_sign_{0}'.format(n), label='{FS}, $Q_H = 2^{{{0}}}$'.format(qh, **strings),
            color=colors[i], linestyle=linestyles[i % len(linestyles)], **pargs)

  ax = pargs['ax']
  for a in annotate:
    a.plot(ax)

  # title and labels
  # ax.set_title('Runtime vs. Signature size with increasing q_H'.format(k))
  ax.set_ylabel('Time [ms]')
  ax.set_xlabel('Size [kB]')

  # legend
  handles, labels = ax.get_legend_handles_labels()
  plt.legend(handles, labels, loc='upper right')

  # grid and ticks
  ax.xaxis.set_major_locator(plticker.MultipleLocator(50))
  ax.yaxis.set_major_locator(plticker.MultipleLocator(25))
  ax.xaxis.set_major_formatter(ScalarFormatterLim(0, 200, 100))
  ax.yaxis.set_major_formatter(ScalarFormatterLim(0, 100, 100))
  ax.grid(True, axis='y', which='both')

  plt.savefig('qh-{0}.eps'.format(prefix))
  plt.savefig('qh-{0}.pdf'.format(prefix))


def main():
  sns.set(style='white', context='paper', font='CMU Serif')
  sns.set_style('white', {
    'legend.frameon': True,
    'text.usetex': True,
    'font.family': 'CMU Serif',
    'font.serif': ['CMU Serif']
  })

  parser = argparse.ArgumentParser(description='Create graphs')
  parser.add_argument('-p', '--prefix', help='prefix of mat files',
                      default='timings')
  parser.add_argument('-s', '--style', help='JSON file with style info', default='style.json')
  subparsers = parser.add_subparsers()

  thread_parser = subparsers.add_parser('omp', help='OpenMP graphs')
  thread_parser.set_defaults(func=create_omp_graphs)
  thread_parser.add_argument('-t', '--threads', help='# of OpenMP threads', type=int, default=4)
  thread_parser.add_argument('--bg-keysize', help='LowMC key size for BG',
                             choices=[128, 192, 256, 384, 448, 512], required=True, type=int)
  thread_parser.add_argument('--bg-blocksize', help='LowMC block size for BG',
                             choices=[128, 192, 256, 384, 448, 512], required=True, type=int)

  default_parser = subparsers.add_parser('default', help='Size vs Runtime graphs')
  default_parser.set_defaults(func=create_graphs)
  default_parser.add_argument('--bg-keysize', help='LowMC key size for BG',
                      choices=[128, 192, 256, 384, 448, 512], required=True, type=int)
  default_parser.add_argument('--bg-blocksize', help='LowMC block size for BG',
                      choices=[128, 192, 256, 384, 448, 512], required=True, type=int)
  default_parser.add_argument('--fs-keysize', help='LowMC key size for FS',
                      choices=[128, 192, 256, 384, 448, 512], required=True, type=int)
  default_parser.add_argument('--fs-blocksize', help='LowMC block size for FS',
                      choices=[128, 192, 256, 384, 448, 512], required=True, type=int)
  default_parser.add_argument('--bg-annotate', help='Pick BG instance to annotate',
                              dest='bg_annotate')
  default_parser.add_argument('--fs-annotate', help='Pick FS instance to annotate',
                              dest='fs_annotate')
  default_parser.add_argument('--sha-size', help='Size of the proof for SHA-256',
                              dest='sha_size', default=mpc_sha256_size, type=float)
  default_parser.add_argument('--sha-verify', help='Runtime of the proof verification for SHA-256',
                              dest='sha_verify', default=mpc_sha256_verify, type=float)
  default_parser.add_argument('--sha-proof', help='Runtime of the proof generation for SHA-256',
                              dest='sha_proof', default=mpc_sha256_proof, type=float)

  qh_parser = subparsers.add_parser('qH', help='graphs for rising q_H')
  qh_parser.set_defaults(func=create_qh_graphs)
  qh_parser.add_argument('--bg-keysize', help='LowMC key size for BG',
                      choices=[128, 192, 256, 384, 448, 512], required=True, type=int)
  qh_parser.add_argument('--bg-blocksize', help='LowMC block size for BG',
                      choices=[128, 192, 256, 384, 448, 512], required=True, type=int)
  qh_parser.add_argument('--bg-annotate', help='Pick BG instance to annotate', dest='bg_annotate')
  qh_parser.add_argument('--fs-annotate', help='Pick FS instance to annotate', dest='fs_annotate')
  qh_parser.add_argument('--annotate-extreme', help='Annotate min/max points',
                        dest='annotate_extreme', default=False, action='store_true')
  qh_parser.add_argument('fsblocksizes', help='LowMC block size for FS', type=int,
                      choices=[128, 192, 256, 384, 448, 512], nargs='+')

  args = parser.parse_args()

  style = None
  if args.style:
    with open(args.style, 'r') as s:
      style = json.load(s)

  args.func(args, style)


if __name__ == '__main__':
  main()

# vim: tw=100 sts=2 sw=2 et
