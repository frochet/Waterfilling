/**
 * \file mt_crypto.c
 *
 * This module provides a simplified interface for cryptographic operations
 * required from by the moneTor payment scheme. Since the original design of
 * moneTor does the include a fully functional cryptographic suite, the
 * high-level operations all redirect to this module. The intent is that code in
 * this module can eventually be redirected to real cryptographic libraries with
 * minimal change to the otherwise functional moneTor code body.
 *
 * A breakdown of cryptographic topics in this module are as follows. The
 * implemention is a combination of real openssl calls and approximations that
 * are sufficient for simulation purposes. In the case of simulated
 * cryptography, cpu delays are added and messages are appropriately padded to
 * size.
 *
 * - KeyGen (RSA): Openssl; fully functional. Keys are imported and exported as
 *   PEM formatted c-strings
 * - Hash Function: Openssl; fully functional
 * - Random Function: Openssl; fully functional
 * - Message Signing: Openssl; fully functional
 *
 * - Commitment: Simulation; messages are committed using a naive one-step
 *   hashing scheme that is incompatible with the final system requirements
 * - Blind Signatures: Simulation; messages are signed by not really blinded
 * - Zero-Knowledge Proofs: Simulation; no effort whatsoever to implement
 *   outside of the delay
 */

#include <string.h>
#include <time.h>

#include <glib.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include "mt_crypto.h"

#define PEM_LINE_SIZE 64

//------------------ Cryptographic Simulate Delays (microsec) ---------------//

#define MT_DELAY_COM_COMMIT 0
#define MT_DELAY_COM_DECOMMIT 0
#define MT_DELAY_BSIG_BLIND 0
#define MT_DELAY_BSIG_UNBLIND 0
#define MT_DELAY_BSIG_VERIFY 0
#define MT_DELAY_ZKP_PROVE 1000000
#define MT_DELAY_ZKP_VERIFY 0

//--------------------------------------------------------------------------//

// global parameters for key generation
int num_bits = 1024;
char* exp_str = "65537";

// random byte string used to simulate a "blinder" for bsig operations
byte* bsig_fake_blinder = (byte*)"1234567812345678123456781234567812345678";

char* pk_header = "-----BEGIN PUBLIC KEY-----\n";
char* pk_footer = "-----END PUBLIC KEY-----\n";
char* sk_header = "-----BEGIN RSA PRIVATE KEY-----\n";
char* sk_footer = "-----END RSA PRIVATE KEY-----\n";

/**
 * Call system nanosleep() to delay the thread for given the microseconds
 */
void micro_sleep(int microsecs){
    struct timespec delay;
    delay.tv_sec = microsecs / 1000000;
    delay.tv_nsec = 0;
    nanosleep(&delay, NULL);
}

/**
 * Convert a base64 encoded PEM string into a decoded output
 */
void decode_key(char* in, byte* out){
    //strip header and footer
    int body_start;
    int body_end;

    for(int i = 0; in[i] != '\n'; i++)
	body_start = i + 1;

    for(int i = strlen(in) - 2; in[i] != '\n'; i--)
	body_end = i;

    char in_body[body_end + 1];
    memcpy(in_body, in + body_start, body_end - body_start);
    in_body[body_end - body_start] = '\0';
    unsigned long decoded_size;
    byte* decoded = g_base64_decode(in_body, &decoded_size);
    memcpy(out, decoded, decoded_size);
    g_free(decoded);
}

/**
 * Convert raw bytes into a base64 PEM-style string with the given header,
 * footer, and linebreaks every 64 characters
 */
void encode_key(char* header, char* footer, byte* in, int in_size, char** out){
    char* encoded = g_base64_encode(in, in_size);

    int newlines = (strlen(encoded) + PEM_LINE_SIZE - 1) / PEM_LINE_SIZE;
    int out_size = strlen(header) + strlen(encoded) + strlen(footer) + newlines;
    *out = malloc(out_size + 1);

    // copy header and footer
    memcpy(*out, header, strlen(header));
    memcpy(*out + strlen(header) + strlen(encoded) + newlines, footer,  strlen(footer));
    (*out)[out_size] = '\0';

    for(int i = strlen(header); i < strlen(header) + strlen(encoded) + newlines;  i++)
	(*out)[i] = '1';

    // copy encoded in 64 byte increments
    char* pos1 = *out + strlen(header);
    char* pos2 = encoded;
    for(int i = 0; i < newlines - 1; i++){
	memcpy(pos1, pos2, PEM_LINE_SIZE);
	pos1 += PEM_LINE_SIZE;
	pos2 += PEM_LINE_SIZE;
	*pos1 = '\n';
	pos1++;
    }
    memcpy(pos1, pos2, strlen(pos2));
    pos1 += strlen(pos2);
    *pos1 = '\n';

    g_free(encoded);
}

/**
 * Called at system setup to obtain public parameters
 */
int mt_crypt_setup(byte (*pp_out)[MT_SZ_PP]){
    return mt_crypt_rand_bytes(MT_SZ_PP, *pp_out);
}

/**
 * Generate a public and private keypair outputted as RSA PEM c-strings. For
 * simulation purposes, keys are simply RSA keys. In the final implementation,
 * it may be necessary for the keys to carry extra information for ZKP scheme
 */
int mt_crypt_keygen(byte (*pp)[MT_SZ_PP], byte (*pk_out)[MT_SZ_PK], byte  (*sk_out)[MT_SZ_SK]){

    // generate the rsa struct
    BIGNUM *exponent = BN_new();
    BN_dec2bn(&exponent, exp_str);
    RSA* rsa = RSA_new();
    if(RSA_generate_key_ex(rsa, num_bits, exponent, NULL) != 1)
	return MT_ERROR;

    // write public key in PEM form
    BIO* bio_pk = BIO_new(BIO_s_mem());
    if(PEM_write_bio_RSA_PUBKEY(bio_pk, rsa) != 1)
	return MT_ERROR;

    int pk_encoded_size = BIO_pending(bio_pk);
    char pk_encoded[pk_encoded_size];
    BIO_read(bio_pk, pk_encoded, pk_encoded_size);
    (pk_encoded)[pk_encoded_size] = '\0';

    // decode PEM public key into a smaller byte string
    byte pk_decoded[MT_SZ_PK];
    decode_key(pk_encoded, pk_decoded);
    memcpy(*pk_out, pk_decoded, MT_SZ_PK);

    // write private key
    BIO* bio_sk = BIO_new(BIO_s_mem());
    if(PEM_write_bio_RSAPrivateKey(bio_sk, rsa, NULL, NULL, 0, NULL, NULL) != 1)
	return MT_ERROR;

    int sk_encoded_size = BIO_pending(bio_sk);
    char sk_encoded[sk_encoded_size];
    BIO_read(bio_sk, sk_encoded, sk_encoded_size);
    (sk_encoded)[sk_encoded_size] = '\0';

    // decode PEM public key into a smaller byte string
    byte sk_decoded[MT_SZ_SK];
    decode_key(sk_encoded, sk_decoded);
    memcpy(*sk_out, sk_decoded, MT_SZ_SK);

    RSA_free(rsa);
    BIO_free(bio_pk);
    BIO_free(bio_sk);

    return MT_SUCCESS;
}

/**
 * Write the specified number of random bytes to the provided buffer
 */
int mt_crypt_rand_bytes(int size, byte* rand_out){
    if(RAND_bytes(rand_out, size) != 1){
	if(RAND_pseudo_bytes(rand_out, size) != 1){
	    return MT_ERROR;
	}
    }
    return MT_SUCCESS;
}

/**
 * Hash the provided message and write to the buffer
 */
int mt_crypt_hash(byte* msg, int msg_size, byte (*hash_out)[MT_SZ_HASH]){
    SHA256_CTX context;

    if(SHA256_Init(&context) != 1)
	return MT_ERROR;

    if(SHA256_Update(&context, (unsigned char*)msg, msg_size) != 1)
	return MT_ERROR;

    if(SHA256_Final(*hash_out, &context) != 1)
	return MT_ERROR;

    return MT_SUCCESS;
}

/**
 * Accept a message of arbitrary length, compute the digest, and output a signature
 */
int mt_sig_sign(byte* msg, int msg_size, byte (*sk_in)[MT_SZ_SK], byte (*sig_out)[MT_SZ_SIG]){

    char* sk;
    encode_key(sk_header, sk_footer, *sk_in, MT_SZ_SK, &sk);

    BIO* bio = BIO_new_mem_buf(sk, strlen(sk));
    RSA* rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);

    if(bio == NULL || rsa == NULL)
	return MT_ERROR;

    byte digest[MT_SZ_HASH];
    if(mt_crypt_hash(msg, msg_size, &digest) != 0)
	return MT_ERROR;

    uint sig_len;
    if(RSA_sign(NID_sha256, digest, MT_SZ_HASH, *sig_out, &sig_len, rsa) != 1)
	return MT_ERROR;

    if(sig_len != MT_SZ_SIG)
	return MT_ERROR;

    free(sk);
    RSA_free(rsa);
    BIO_free(bio);
    return MT_SUCCESS;
}

/**
 * Accept a message of arbitrary length, compute the digest, and verify the
 * provided signature
 */
int mt_sig_verify(byte* msg, int msg_size, byte (*pk_in)[MT_SZ_PK], byte   (*sig)[MT_SZ_SIG]){

    char* pk;
    encode_key(pk_header, pk_footer, *pk_in, MT_SZ_PK, &pk);

    BIO* bio = BIO_new_mem_buf(pk, strlen(pk));
    RSA* rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);

    if(bio == NULL || rsa == NULL)
	return MT_ERROR;

    byte digest[MT_SZ_HASH];
    if(mt_crypt_hash(msg, msg_size, &digest) != MT_SUCCESS)
	return MT_ERROR;

    // signature did not verify
    if(RSA_verify(NID_sha256, digest, MT_SZ_HASH, *sig, MT_SZ_SIG, rsa) != 1)
	return MT_ERROR;

    free(pk);
    RSA_free(rsa);
    BIO_free(bio);
    return MT_SUCCESS;
}

/**
 * Accept a message of arbitrary length along with some random bytes and compute a
 * commitment. In this simulated environment, the commitment is simply a hash of
 * the message concatenated with the random bytes
 */
int mt_com_commit(byte* msgs, int msg_size, byte (*rand)[MT_SZ_HASH], byte (*com_out)[MT_SZ_COM]){
    byte* concated = malloc(msg_size + MT_SZ_HASH);
    memcpy(concated, msgs, msg_size);
    memcpy(concated + msg_size, *rand, MT_SZ_HASH);

    byte digest[MT_SZ_HASH];
    if(mt_crypt_hash(concated, msg_size + MT_SZ_HASH, &digest) != MT_SUCCESS)
	return MT_ERROR;

    // commitment in the final scheme may be larger than hash; pad the difference
    memcpy(*com_out, digest, MT_SZ_HASH);
    if(mt_crypt_rand_bytes(MT_SZ_COM - MT_SZ_HASH, (*com_out) + MT_SZ_HASH) !=  MT_SUCCESS)
	return MT_ERROR;

    micro_sleep(MT_DELAY_COM_COMMIT);
    return MT_SUCCESS;
}

/**
 * Verify the commitment provided for a message of arbitrary length
 */
int mt_com_decommit(byte* msg, int msg_size, byte (*rand)[MT_SZ_HASH], byte  (*com)[MT_SZ_COM]){
    byte com_ver[MT_SZ_COM];
    if(mt_com_commit(msg, msg_size, rand, &com_ver) != MT_SUCCESS)
	return MT_ERROR;
    if(memcmp(com, com_ver, MT_SZ_HASH) != 0)
	return MT_ERROR;

    micro_sleep(MT_DELAY_COM_DECOMMIT);
    return MT_SUCCESS;
}

/**
 * Accept a message of arbitrary length and "blind" it so that it can be signed
 * anonymously. In this simulated version, the blinding is simply an operation
 * with the globally visible bsig_fake_blinder string. The unblinder does
 * nothing and is simply filled with random bytes
 */
int mt_bsig_blind(byte *msg, int msg_size, byte (*pk)[MT_SZ_PK], byte (*blinded_out)[MT_SZ_BL],
		byte(*unblinder_out)[MT_SZ_UBLR]){

    byte digest[MT_SZ_HASH];
    if(mt_crypt_hash(msg, msg_size, &digest) != MT_SUCCESS)
	return MT_ERROR;

    for(int i = 0; i < MT_SZ_BL; i++)
	(*blinded_out)[i] = bsig_fake_blinder[i % MT_SZ_HASH] ^ digest[i % MT_SZ_HASH];

    if(mt_crypt_rand_bytes(MT_SZ_UBLR, *unblinder_out) != MT_SUCCESS)
	return MT_ERROR;

    micro_sleep(MT_DELAY_BSIG_BLIND);
    return MT_SUCCESS;
}

/**
 * Accept a signature on a blinded message and unblind it so it can be verified
 * later. Since we do not having a real blinding scheme, this simply copies over
 * the "blinded" signature to the "unblinded" buffer.
 */
int mt_bsig_unblind(byte (*pk)[MT_SZ_PK], byte (*blinded_sig)[MT_SZ_SIG], byte (*unblinder)[MT_SZ_UBLR],
		  byte (*unblinded_sig_out)[MT_SZ_SIG]){
    memcpy(*unblinded_sig_out, *blinded_sig, MT_SZ_SIG);
    micro_sleep(MT_DELAY_BSIG_UNBLIND);
    return MT_SUCCESS;
}

/**
 * Verify an unblinded signature on the original message. This is easy for the
 * simulated version since the message simply needs to be put through the fake
 * blinding process to verify with the signature.
 */
int mt_bsig_verify(byte* msg, int msg_size, byte (*pk)[MT_SZ_PK], byte (*unblinded_sig)[MT_SZ_SIG]){

    byte* blinded = malloc(MT_SZ_BL);

    byte digest[MT_SZ_HASH];
    if(mt_crypt_hash(msg, msg_size, &digest) != MT_SUCCESS)
	return MT_ERROR;

    for(int i = 0; i < MT_SZ_BL; i++)
	blinded[i] = bsig_fake_blinder[i % MT_SZ_HASH] ^ digest[i % MT_SZ_HASH];

    if(mt_sig_verify(blinded, MT_SZ_BL, pk, unblinded_sig) != MT_SUCCESS)
	return MT_ERROR;

    micro_sleep(MT_DELAY_BSIG_VERIFY);
    return MT_SUCCESS;
}

/**
 * Accept some inputs and compute a zero-knowledge proof on some statements
 * about the input. We do not even attempt to implement this in the simulated
 * scheme. Only the bare minimum computations are done so that proofs are not
 * accidently rejected or confused with other proofs in the simulation.
 */
int mt_zkp_prove(byte (*pp)[MT_SZ_PP], byte* inputs, int input_size, byte (*zkp_out)[MT_SZ_ZKP]){
    // override output with pp xor'd with some constant string

    byte digest[MT_SZ_HASH];
    if(mt_crypt_hash(inputs, input_size, &digest) != MT_SUCCESS)
	return MT_ERROR;

    memcpy(*zkp_out, *pp, MT_SZ_HASH / 2);
    memcpy((*zkp_out) + MT_SZ_HASH / 2, digest, MT_SZ_HASH / 2);

    if(mt_crypt_rand_bytes(MT_SZ_ZKP - MT_SZ_HASH, (*zkp_out) + MT_SZ_HASH) !=  MT_SUCCESS)
	return MT_ERROR;

    micro_sleep(MT_DELAY_ZKP_PROVE);
    return MT_SUCCESS;
}

/**
 * Accept some zero-knowledge proof and verify its correctness. In the simulated
 * version, we do a simple sanity check to make sure that the proof was at least
 * likely to be generated on purpose in some other part of the simulation.
 */
int mt_zkp_verify(byte (*pp)[MT_SZ_PP], byte (*proof)[MT_SZ_ZKP]){
    // override output with pp xor'd with some constant string
    if(memcmp(proof, pp, MT_SZ_HASH / 2) != 0)
	return MT_ERROR;

    micro_sleep(MT_DELAY_ZKP_VERIFY);
    return MT_SUCCESS;
}
