#ifndef MPC_LOWMC_H
#define MPC_LOWMC_H

#include <m4ri/m4ri.h>
#include <stdbool.h>

#include "lowmc_pars.h"
#include "parameters.h"

typedef mzd_shared_t mpc_lowmc_key_t;

typedef lowmc_t mpc_lowmc_t;

typedef struct {
  mzd_t **s;
} view_t;

typedef struct {
  view_t **views;
  unsigned char ***keys;
  unsigned char ***r;
  unsigned char hashes[NUM_ROUNDS][COMMITMENT_LENGTH];
  unsigned char ch[(NUM_ROUNDS + 3) / 4];
  mzd_t ***y;
} proof_t;

proof_t *proof_from_char_array(mpc_lowmc_t *lowmc, proof_t *proof, unsigned char *data, unsigned *len, bool contains_ch);

unsigned char *proof_to_char_array(mpc_lowmc_t *lowmc, proof_t *proof, unsigned *len, bool store_ch); 

proof_t *create_proof(proof_t* proof, mpc_lowmc_t const* lowmc,
                      unsigned char hashes[NUM_ROUNDS][3][COMMITMENT_LENGTH],
                      unsigned char ch[NUM_ROUNDS], unsigned char r[NUM_ROUNDS][3][4],
                      unsigned char keys[NUM_ROUNDS][3][16], mzd_t*** c_mpc,
                      view_t* const views[NUM_ROUNDS]);

void clear_proof(mpc_lowmc_t const *lowmc, proof_t const *proof);
void free_proof(mpc_lowmc_t const *lowmc, proof_t *proof);

/**
 * Initializes the views for the MPC execution of LowMC
 *
 * \param  lowmc the lowmc parameters
 * \return       an array containing the initialized views 
 */
mzd_t **mpc_init_views(mpc_lowmc_t *lowmc);

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
mzd_t **mpc_lowmc_call(mpc_lowmc_t const *lowmc, mpc_lowmc_key_t *lowmc_key, mzd_t const *p, view_t *views, mzd_t ***rvec);

/**
 * Verifies a ZKBoo execution of a LowMC encryption
 *
 * \param  lowmc     the lowmc parameters
 * \param  p         the plaintext
 * \param  views     the views
 * \param  rvec      the randomness vector
 * \return           0 on success and a value != 0 otherwise
 */
int mpc_lowmc_verify(mpc_lowmc_t const *lowmc, mzd_t const *p, view_t const *views, mzd_t ***rvec, int c);

/**
 * Implements MPC LowMC encryption according to
 * https://eprint.iacr.org/2016/163.pdf with shared plaintext.
 *
 * \param  lowmc     the lowmc parameters
 * \param  lowmc_key the lowmc key
 * \param  p         the plaintext
 * \param  views     the views
 * \param  rvec      the randomness vector
 * \return           the ciphertext
 */
mzd_t **mpc_lowmc_call_shared_p(mpc_lowmc_t const *lowmc, mpc_lowmc_key_t *lowmc_key, mzd_shared_t const* p, view_t *views,
                       mzd_t ***rvec);

/**
 * Verifies a ZKBoo execution of a LowMC encryption with shared plaintext.
 *
 * \param  lowmc     the lowmc parameters
 * \param  p         the plaintext
 * \param  views     the views
 * \param  rvec      the randomness vector
 * \return           0 on success and a value != 0 otherwise
 */
int mpc_lowmc_verify_shared_p(mpc_lowmc_t const *lowmc, mzd_shared_t const* p, view_t const *views, mzd_t ***rvec, int c);


#endif
