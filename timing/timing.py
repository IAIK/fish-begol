import argparse
import subprocess

def main():
  args = parse_args()
  k = args.keysize
  with open(args.filename) as f:
    for line in f.readlines():
      if line.rstrip():
        m, n, r = get_params(line)
        timings = open("timings-{0}-{1}-{2}-{3}.csv".format(m, n, r, k), "w")
        subprocess.Popen("./{0} {1} {2} {3} {4} {5}".format(args.executable, 
                         m, n, r, k, args.iterations), shell=True, stdout=timings).wait()
      
      
    
def get_params(line):
  l = line.split()
  d = dict(zip(l[::2], l[1::2]))
  print d
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
  args = parser.parse_args()
  return args

if __name__ == "__main__":
    main()
