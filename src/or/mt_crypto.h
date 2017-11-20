/**
   \file mt_crypto.h

   This module serves as a cryptographic library for all payment-related moneTor
   operations. Some calls (such as hashing) will perform real operations while
   others (such as zero knowledge proofs) are simply modeled as a time delay.
*/

#ifndef mt_crypto_h
#define mt_crypto_h

#include "mt.h"

// common
int mt_crypt_setup(byte (*pp_out)[MT_SZ_PP]);
int mt_crypt_keygen(byte (*pp)[MT_SZ_PP], byte (*pk_out)[MT_SZ_PK], byte (*sk_out)[MT_SZ_SK]);
int mt_crypt_rand_bytes(int size, byte* rand_out);
int mt_crypt_hash(byte* msg, int msg_size, byte (*hash_out)[MT_SZ_HASH]);

// signature scheme
int mt_sig_sign(byte* msg, int msg_size, byte (*sk)[MT_SZ_SK], byte (*sig_out)[MT_SZ_SIG]);
int mt_sig_verify(byte* msg, int msg_size, byte (*pk)[MT_SZ_PK], byte (*sig)[MT_SZ_SIG]);

// commitment scheme
int mt_com_commit(byte* msg, int msg_size, byte (*rand)[MT_SZ_HASH], byte (*com_out)[MT_SZ_COM]);
int mt_com_decommit(byte* msg, int msg_size, byte (*rand)[MT_SZ_HASH], byte (*com)[MT_SZ_COM]);

// blind signature scheme
int mt_bsig_blind(byte* msg, int msg_size, byte (*pk)[MT_SZ_PK], byte (*blinded_out)[MT_SZ_BL],
		byte(*unblinder_out)[MT_SZ_UBLR]);
int mt_bsig_unblind(byte (*pk)[MT_SZ_PK], byte (*blinded_sig)[MT_SZ_SIG], byte (*unblinder)[MT_SZ_UBLR],
		  byte (*unblinded_sig_out)[MT_SZ_SIG]);
int mt_bsig_verify(byte* msg, int msg_size, byte (*pk)[MT_SZ_PK], byte (*unblinded_sig)[MT_SZ_SIG]);

// zero-knowledge proof of wallet validity
int mt_zkp_prove(byte (*pp)[MT_SZ_PP], byte* inputs, int input_size, byte (*zkp_out)[MT_SZ_ZKP]);
int mt_zkp_verify(byte (*pp)[MT_SZ_PP], byte (*proof)[MT_SZ_ZKP]);

#endif
