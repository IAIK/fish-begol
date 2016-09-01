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

static void print_timings(clock_t** timings, int iter, int numt) {
  for(unsigned i = 0 ; i < iter ; i++) {
    for(unsigned j = 0 ; j < numt ; j++) {
      printf("%lu", timings[i][j]);
      if(j < 12) printf(",");
    }
    printf("\n");
  } 
}

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

  char m[10] = "1234567890";

  clock_t **timings_fis = (clock_t**)malloc(args[4] * sizeof(clock_t*));
  for(int i = 0 ; i < args[4] ; i++)
    timings_fis[i] = (clock_t*)malloc(13 * sizeof(clock_t));  

  for (int i = 0; i != args[4]; ++i) {
    public_parameters_t pp;
    fis_private_key_t private_key;
    fis_public_key_t public_key;

    create_instance(&pp, timings_fis[i], args[0], args[1], args[2], args[3]);
    fis_create_key(&pp, &private_key, &public_key, timings_fis[i]);

    lowmc_key_t key = { 0, NULL };
    mzd_shared_copy(&key, private_key.k);

    fis_signature_t* sig = fis_sign(&pp, &private_key, m, timings_fis[i]);

    unsigned char *data = fis_sig_to_char_array(&pp, sig);
    fis_signature_t *sigr = fis_sig_from_char_array(&pp, data);

    if(fis_verify(&pp, &public_key, m, sigr, timings_fis[i])) {
      printf("error\n");
    }

    fis_destroy_signature(&pp, sig);
    mzd_shared_clear(&key);

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
    timings_bg[i] = (clock_t*)malloc(13 * sizeof(clock_t));  

  for (int i = 0; i != args[4]; ++i) {
    public_parameters_t pp;
    bg_private_key_t private_key;
    bg_public_key_t public_key;

    create_instance(&pp, timings_bg[i], args[0], args[1], args[2], args[3]);
    bg_create_key(&pp, &private_key, &public_key, timings_bg[i]);

    mzd_t* p = mzd_init_random_vector(args[1]);

#ifdef VERBOSE
    clock_t beginRef = clock();
#endif
    mzd_t* c         = lowmc_call(pp.lowmc, private_key.s, p);
#ifdef VERBOSE
    clock_t deltaRef = (clock() - beginRef) * TIMING_SCALE;
    printf("LowMC reference encryption    %6lu\n", deltaRef);
    printf("\n");
#endif

    bg_signature_t* signature = bg_prove(&pp, &private_key, p, timings_bg[i]);
    bg_verify(&pp, &public_key, p, c, signature, timings_bg[i]);

    bg_free_signature(&pp, signature);
 
    mzd_free(p);
    mzd_free(c);

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
  init_EVP();
  openmp_thread_setup();
 
  int args[5];
  parse_args(args, argc, argv);

  fis_sign_verify(args);
  bg_sign_verify(args);

  openmp_thread_cleanup();
  cleanup_EVP();
  return 0;
}
