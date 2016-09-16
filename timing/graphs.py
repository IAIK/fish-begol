import argparse
import h5py
import numpy as np
import matplotlib
import matplotlib.pyplot as plt
import pandas as pd

def create_graph(prefix, n, k, data, labels):
  data = np.array(data)

  size = data[:, 12] / 1024
  sign = np.sum(data[:, 3:7] / 1000, axis=1)
  verify = np.sum(data[:, 8:12] / 1000, axis=1)

  df = pd.DataFrame({
      'sign': pd.Series(sign, index=labels),
      'verify': pd.Series(verify, index=labels),
      'size': pd.Series(size, index=labels)
  })

  style = {
      'sign': ['marker', '.','markersize', 8, 'color', 'blue', 'linewidth', 2],
      'verify': ['marker', 'diamond','markersize', 2, 'color', 'red', 'linewidth', 2],
      'size': ['marker', '>','markersize', 2, 'color', 'green', 'linewidth', 2]
  }

  marker={'sign': '.', 'verify': 'diamond', 'size': '>'}

  plt.figure(figsize=(6, 6 * 3 / 4.0))
  ax = df.plot(secondary_y=['size'], mark_right=False, marker='>',
               markersize=8, linewidth=3, legend=False)

  # title and labels
  ax.set_title('LowMC Timing n={0} k={1} - Parameters [m]-[r])'.format(n, k))
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


def main(args):
  n = args.blocksize
  k = args.keysize
  prefix = args.prefix

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
  args = parser.parse_args()

  main(args)

