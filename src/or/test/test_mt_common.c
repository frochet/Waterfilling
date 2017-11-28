#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "../mt.h"
#include "../mt_crypto.h"
#include "../mt_tokens.h"
#include "../mt_common.h"
#include "test_mt_main.h"

void test_mt_common(){

    byte pp[MT_SZ_PP];
    byte pk[MT_SZ_PK];
    byte sk[MT_SZ_SK];

    mt_crypt_setup(&pp);
    mt_crypt_keygen(&pp, &pk, &sk);

    //----------------------------- Test PK to Address ---------------------------//

    byte pk_copy[MT_SZ_PK];
    byte pk_diff[MT_SZ_PK];
    byte sk_diff[MT_SZ_SK];

    memcpy(pk_copy, pk, MT_SZ_PK);
    mt_crypt_keygen(&pp, &pk_diff, &sk_diff);

    byte addr[MT_SZ_ADDR];
    byte addr_copy[MT_SZ_ADDR];
    byte addr_diff[MT_SZ_ADDR];

    mt_pk2addr(&pk, &addr);
    mt_pk2addr(&pk_copy, &addr_copy);
    mt_pk2addr(&pk_diff, &addr_diff);

    assert(memcmp(addr, addr_copy, MT_SZ_ADDR) == 0);
    assert(memcmp(addr, addr_diff, MT_SZ_ADDR) != 0);

    //----------------------------- Test Address to Hex --------------------------//

    byte addr_str[MT_SZ_ADDR] = "20 bytes ++)(*_*)///";
    char expected_hex[MT_SZ_ADDR * 2 + 3] = "0x3230206279746573202B2B29282A5F2A292F2F2F\0";
    char hex_out[MT_SZ_ADDR * 2 + 3];

    mt_addr2hex(&addr_str, &hex_out);

    assert(memcmp(expected_hex, hex_out, strlen(hex_out)) == 0);

    //----------------------------- Test Hash Chains -----------------------------//

    int hc_size = 1000;
    byte head[MT_SZ_HASH];
    byte hc[hc_size][MT_SZ_HASH];

    mt_crypt_rand_bytes(MT_SZ_HASH, head);
    mt_hc_create(hc_size, &head, &hc);

    // make sure correct hashes are correct
    assert(mt_hc_verify(&(hc[0]), &(hc[0]), 0) == MT_SUCCESS);
    assert(mt_hc_verify(&(hc[0]), &(hc[hc_size / 2]), hc_size / 2) == MT_SUCCESS);
    assert(mt_hc_verify(&(hc[0]), &(hc[hc_size - 1]), hc_size - 1) == MT_SUCCESS);

    // make sure incorrect hashes are incorrect
    assert(mt_hc_verify(&(hc[0]), &(hc[hc_size - 1]), 0) == MT_ERROR);
    assert(mt_hc_verify(&(hc[0]), &(hc[hc_size / 2]), hc_size / 3 - 1) == MT_ERROR);
    assert(mt_hc_verify(&(hc[0]), &(hc[0]), hc_size) == MT_ERROR);

    //----------------------------- Test Commit Wallet ---------------------------//

    //----------------------------- Test Verify Refund ---------------------------//

}
