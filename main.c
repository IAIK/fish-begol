#include "hashing_util.h"
#include "lowmc.h"
#include "lowmc_pars.h"
#include "mpc.h"
#include "mpc_lowmc.h"
#include "mpc_test.h"
#include "multithreading.h"
#include "mzd_additional.h"
#include "randomness.h"
#include "signature_common.h"
#include "signature_bg.h"
#include "signature_fis.h"
#include "io.h"

#include <inttypes.h>

#include <time.h>

#ifndef VERBOSE
static void print_timings(clock_t** timings, int iter, int numt) {
  for(unsigned i = 0 ; i < iter ; i++) {
    for(unsigned j = 0 ; j < numt ; j++) {
      printf("%lu", timings[i][j]);
      if(j < numt - 1) printf(",");
    }
    printf("\n");
  } 
}
#endif

void parse_args(int params[5], int argc, char **argv) {
  if(argc != 6) {
    printf("Usage ./mpc_lowmc [Number of SBoxes] [Blocksize] [Rounds] [Keysize] [Numiter]\n"); 
    exit(-1);
  }
  params[0] = atoi(argv[1]);
  params[1] = atoi(argv[2]);
  params[2] = atoi(argv[3]);
  params[3] = atoi(argv[4]);
  params[4] = atoi(argv[5]);
}

static void fis_sign_verify(int args[5]) {
#ifdef VERBOSE
  printf("Fiat-Shamir Signature:\n\n");
#endif

  char m[11] = "1234567890";

  clock_t **timings_fis = (clock_t**)malloc(args[4] * sizeof(clock_t*));
  for(int i = 0 ; i < args[4] ; i++)
    timings_fis[i] = (clock_t*)calloc(13, sizeof(clock_t));  

  for (int i = 0; i != args[4]; ++i) {
    public_parameters_t pp;
    fis_private_key_t private_key;
    fis_public_key_t public_key;

    create_instance(&pp, timings_fis[i], args[0], args[1], args[2], args[3]);
    fis_create_key(&pp, &private_key, &public_key, timings_fis[i]);

    fis_signature_t* sig = fis_sign(&pp, &private_key, m, timings_fis[i]);

    unsigned len = 0;
    unsigned char *data = fis_sig_to_char_array(&pp, sig, &len);
    timings_fis[i][12] = fis_compute_sig_size(pp.lowmc->m, pp.lowmc->n, pp.lowmc->r, pp.lowmc->k);
    fis_free_signature(&pp, sig);
    sig = fis_sig_from_char_array(&pp, data);
    free(data);

    if(fis_verify(&pp, &public_key, m, sig, timings_fis[i])) {
      printf("error\n");
    }

    fis_free_signature(&pp, sig);

    destroy_instance(&pp);
    fis_destroy_key(&private_key, &public_key);
  }

#ifndef VERBOSE
  print_timings(timings_fis, args[4], 13);
#endif

  for(int i = 0; i < args[4] ; i++) 
    free(timings_fis[i]);
  free(timings_fis);
}

static void bg_sign_verify(int args[5]) {
#ifdef VERBOSE
  printf("BG Signature:\n\n");
#endif
  
  clock_t **timings_bg = (clock_t**)malloc(args[4] * sizeof(clock_t*));
  for(int i = 0 ; i < args[4] ; i++)
    timings_bg[i] = (clock_t*)calloc(13, sizeof(clock_t));  

  for (int i = 0; i != args[4]; ++i) {
    public_parameters_t pp;
    bg_private_key_t private_key;
    bg_public_key_t public_key;

    create_instance(&pp, timings_bg[i], args[0], args[1], args[2], args[3]);
    bg_create_key(&pp, &private_key, &public_key, timings_bg[i]);

    mzd_t* m = mzd_init_random_vector(args[1]);

    bg_signature_t* signature = bg_sign(&pp, &private_key, m, timings_bg[i]);

    unsigned len = 0;
    unsigned char *data = bg_sig_to_char_array(&pp, signature, &len);
    timings_bg[i][12] = bg_compute_sig_size(pp.lowmc->m, pp.lowmc->n, pp.lowmc->r, pp.lowmc->k);
    bg_free_signature(&pp, signature);
    signature = bg_sig_from_char_array(&pp, data);
    free(data);

    if(bg_verify(&pp, &public_key, m, signature, timings_bg[i])) {
      printf("error\n");
    }

    bg_free_signature(&pp, signature);

    mzd_free(m);

    destroy_instance(&pp);
    bg_destroy_key(&private_key, &public_key);
  }

#ifndef VERBOSE
  print_timings(timings_bg, args[4], 13);
#endif

  for(int i = 0; i < args[4] ; i++) 
    free(timings_bg[i]);
  free(timings_bg);
}


int main(int argc, char** argv) {
  init_rand_bytes();
  init_EVP();
  openmp_thread_setup();
 
  int args[5];
  parse_args(args, argc, argv);

  fis_sign_verify(args);
  bg_sign_verify(args);

  openmp_thread_cleanup();
  cleanup_EVP();
  deinit_rand_bytes();

  return 0;
}
