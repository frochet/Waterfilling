/**
 * \file mt_crypto.h
 * \brief Header file for mt_crypto.c
 *
 * All functions return MT_SUCCESS/MT_ERROR unless void or otherwise stated.
 **/

#ifndef mt_crypto_h
#define mt_crypto_h

#include "or.h"

/******************************* General ********************************/

/**
 * Generate the public parameters needed to run the
 * commitment/zero-knowledge proof schemes
 */
int mt_crypt_setup(byte (*pp_out)[MT_SZ_PP]);

/**
 * Generate a public/private RSA keypair given public parameters
 */
int mt_crypt_keygen(byte (*pp)[MT_SZ_PP], byte (*pk_out)[MT_SZ_PK], byte (*sk_out)[MT_SZ_SK]);

/**
 * Fill the given byte string with cryptographically secure random
 * bytes of the given size.
 */
int mt_crypt_rand(int size, byte* rand_out);

/**
 * Generate a SHA256 hash digest of the given byte string message
 */
int mt_crypt_hash(byte* msg, int msg_size, byte (*hash_out)[MT_SZ_HASH]);

/******************************* Signature ******************************/

/**
 * Generate signature on a byte string message
 */
int mt_sig_sign(byte* msg, int msg_size, byte (*sk)[MT_SZ_SK], byte  (*sig_out)[MT_SZ_SIG]);

/**
 * Verify the signature on a byte string message
 */
int mt_sig_verify(byte* msg, int msg_size, byte (*pk)[MT_SZ_PK], byte (*sig)[MT_SZ_SIG]);

/******************************* Committment ****************************/

/**
 * Generate a committment on a byte string message and randomness
 */
int mt_com_commit(byte* msg, int msg_size, byte (*rand)[MT_SZ_HASH],  byte (*com_out)[MT_SZ_COM]);

/**
 * Verify committment on the original message and randomness
 */
int mt_com_decommit(byte* msg, int msg_size, byte (*rand)[MT_SZ_HASH], byte (*com)[MT_SZ_COM]);


/****************************** Blind Signature *************************/

/**
 * Generate a blinded version of the given message that can be signed
 * using a compatible signature scheme
 */
int mt_bsig_blind(byte* msg, int msg_size, byte (*pk)[MT_SZ_PK], byte (*blinded_out)[MT_SZ_BL],
		byte(*unblinder_out)[MT_SZ_UBLR]);

/**
 * Given a signature on a blinded message, unblind the signature so
 * that it can be verified against the original message.
 */
int mt_bsig_unblind(byte (*pk)[MT_SZ_PK], byte (*blinded_sig)[MT_SZ_SIG], byte (*unblinder)[MT_SZ_UBLR],
		  byte (*unblinded_sig_out)[MT_SZ_SIG]);

/**
 * Verify an unblinded signature on the original message.
 */
int mt_bsig_verify(byte* msg, int msg_size, byte (*pk)[MT_SZ_PK], byte (*unblinded_sig)[MT_SZ_SIG]);

/*************************** Zero-Knowledge Proof ***********************/

/**
 * Generate a zero-knowledge proof of some encoded statement given
 * some inputs.
 */
int mt_zkp_prove(byte (*pp)[MT_SZ_PP], byte* inputs, int input_size,  byte (*zkp_out)[MT_SZ_ZKP]);

/**
 * Verify a zero-knowledge proof.
 */
int mt_zkp_verify(byte (*pp)[MT_SZ_PP], byte (*proof)[MT_SZ_ZKP]);

#endif
