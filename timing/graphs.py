import argparse
import h5py
import numpy as np
import matplotlib

import matplotlib.pyplot as plt
import pandas as pd

def main(args):
  matplotlib.style.use('ggplot')
  n = args.keysize
  k = args.blocksize
  prefix = args.prefix

  with h5py.File('{0}-{1}-{2}.mat'.format(prefix, n, k), 'r') as timings:
    labels = timings.get("labels")
    fis_sum = timings.get("fis_sum")
    bg_sum = timings.get("bg_sum")

    fis_sum = np.array(fis_sum)
    bg_sum = np.array(bg_sum)

    fis_size = fis_sum[:, 12] / 1024
    bg_size = bg_sum[:, 12] / 1024

    fis_sign = np.sum(fis_sum[:, 3:7] / 1000, axis=1)
    bg_sign = np.sum(bg_sum[:, 3:7] / 1000, axis=1)

    fis_verify = np.sum(fis_sum[:, 8:12] / 1000, axis=1)
    bg_verify = np.sum(bg_sum[:, 8:12] / 1000, axis=1)

    fis_df = pd.DataFrame({
        'sign': pd.Series(fis_sign, index=labels),
        'verify': pd.Series(fis_verify, index=labels),
        'size': pd.Series(fis_size, index=labels)
    })

    style = {
        'sign': ['marker', '.','markersize', 8, 'color', 'blue', 'linewidth', 2],
        'verify': ['marker', 'diamond','markersize', 2, 'color', 'red', 'linewidth', 2],
        'size': ['marker', '>','markersize', 2, 'color', 'green', 'linewidth', 2]
    }

    marker={'sign': '.', 'verify': 'diamond', 'size': '>'}

    ax = fis_df.plot(secondary_y=['size'], mark_right=False, marker='>',
            markersize=8, linewidth=3)
    ax.set_title('LowMC Timing n={0} k={1}'.format(n, k))
    ax.set_ylabel('Time [ms]')
    ax.set_xlabel('Parameters [m]-[r])')
    ax.right_ax.set_ylabel('Size [kB]')
    plt.xticks(range(len(labels)), labels, rotation='vertical')
    plt.savefig('{0}-{1}-{2}.eps'.format(prefix, n, k))
    plt.savefig('{0}-{1}-{2}.png'.format(prefix, n, k))

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

