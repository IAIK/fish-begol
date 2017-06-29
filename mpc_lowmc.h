#ifndef MPC_LOWMC_H
#define MPC_LOWMC_H

#include <m4ri/m4ri.h>
#include <stdbool.h>

#include "lowmc_pars.h"
#include "mzd_shared.h"
#include "parameters.h"

typedef mzd_shared_t mpc_lowmc_key_t;

typedef lowmc_t mpc_lowmc_t;

typedef struct { mzd_t* s[SC_PROOF]; } view_t;

typedef struct {
  view_t* views[NUM_ROUNDS];
  unsigned char keys[NUM_ROUNDS][SC_VERIFY][PRNG_KEYSIZE];
  unsigned char r[NUM_ROUNDS][SC_VERIFY][COMMITMENT_RAND_LENGTH];
  unsigned char hashes[NUM_ROUNDS][COMMITMENT_LENGTH];
  unsigned char ch[(NUM_ROUNDS + 3) / 4];
} proof_t;

proof_t* proof_from_char_array(mpc_lowmc_t* lowmc, proof_t* proof, unsigned char* data,
                               unsigned* len, bool contains_ch);

unsigned char* proof_to_char_array(mpc_lowmc_t* lowmc, proof_t* proof, unsigned* len,
                                   bool store_ch);

proof_t* create_proof(proof_t* proof, mpc_lowmc_t const* lowmc,
                      unsigned char hashes[NUM_ROUNDS][SC_PROOF][COMMITMENT_LENGTH],
                      unsigned char ch[NUM_ROUNDS],
                      unsigned char r[NUM_ROUNDS][SC_PROOF][COMMITMENT_RAND_LENGTH],
                      unsigned char keys[NUM_ROUNDS][SC_PROOF][PRNG_KEYSIZE],
                      view_t* const views[NUM_ROUNDS]);

void clear_proof(mpc_lowmc_t const* lowmc, proof_t const* proof);
void free_proof(mpc_lowmc_t const* lowmc, proof_t* proof);

/**
 * Implements MPC LowMC encryption according to
 * https://eprint.iacr.org/2016/163.pdf
 *
 * \param  lowmc     the lowmc parameters
 * \param  lowmc_key the lowmc key
 * \param  p         the plaintext
 * \param  views     the views
 * \param  rvec      the randomness vector
 * \return           the ciphertext
 */
mzd_t** mpc_lowmc_call(mpc_lowmc_t const* lowmc, mpc_lowmc_key_t* lowmc_key, mzd_t const* p,
                       view_t* views, mzd_t*** rvec);

/**
 * Verifies a ZKBoo execution of a LowMC encryption
 *
 * \param  lowmc     the lowmc parameters
 * \param  p         the plaintext
 * \param  views     the views
 * \param  rvec      the randomness vector
 * \return           0 on success and a value != 0 otherwise
 */
int mpc_lowmc_verify(mpc_lowmc_t const* lowmc, mzd_t const* p, view_t const* views,
                     mzd_t*** rvec, int c);

/**
 * Verifies a ZKBoo execution of a LowMC encryption
 *
 * \param  lowmc     the lowmc parameters
 * \param  p         the plaintext
 * \param  views     the views
 * \param  rvec      the randomness vector
 * \return           0 on success and a value != 0 otherwise
 */
int mpc_lowmc_verify_keys(mpc_lowmc_t const* lowmc, mzd_t const* p, view_t const* views,
                          mzd_t*** rvec, int c, const unsigned char keys[2][16]);

#endif
