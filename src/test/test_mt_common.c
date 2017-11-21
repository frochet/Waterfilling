#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "test.h"
#include "or.h"
#include "mt_crypto.h"
#include "mt_common.h"

static void test_mt_common(void *arg)
{
  (void) arg;

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

    tt_assert(memcmp(addr, addr_copy, MT_SZ_ADDR) == 0);
    tt_assert(memcmp(addr, addr_diff, MT_SZ_ADDR) != 0);

    //----------------------------- Test Address to Hex --------------------------//

    byte addr_str[MT_SZ_ADDR] = "20 bytes ++)(*_*)///";
    char expected_hex[MT_SZ_ADDR * 2 + 3] = "0x3230206279746573202B2B29282A5F2A292F2F2F\0";
    char hex_out[MT_SZ_ADDR * 2 + 3];

    mt_addr2hex(&addr_str, &hex_out);

    tt_assert(memcmp(expected_hex, hex_out, strlen(hex_out)) == 0);

    //----------------------------- Test Hash Chains -----------------------------//

    int hc_size = 1000;
    byte head[MT_SZ_HASH];
    byte hc[1000][MT_SZ_HASH];

    mt_crypt_rand_bytes(MT_SZ_HASH, head);
    mt_hc_create(hc_size, &head, &hc);

    // make sure correct hashes are correct
    tt_assert(mt_hc_verify(&(hc[0]), &(hc[0]), 0) == MT_SUCCESS);
    tt_assert(mt_hc_verify(&(hc[0]), &(hc[hc_size / 2]), hc_size / 2) == MT_SUCCESS);
    tt_assert(mt_hc_verify(&(hc[0]), &(hc[hc_size - 1]), hc_size - 1) == MT_SUCCESS);

    // make sure incorrect hashes are incorrect
    tt_assert(mt_hc_verify(&(hc[0]), &(hc[hc_size - 1]), 0) == MT_ERROR);
    tt_assert(mt_hc_verify(&(hc[0]), &(hc[hc_size / 2]), hc_size / 3 - 1) == MT_ERROR);
    tt_assert(mt_hc_verify(&(hc[0]), &(hc[0]), hc_size) == MT_ERROR);

 done:;
}

struct testcase_t mt_common_tests[] = {
  /* This test is named 'strdup'. It's implemented by the test_strdup
   * function, it has no flags, and no setup/teardown code. */
  { "mt_common", test_mt_common, 0, NULL, NULL },
  END_OF_TESTCASES
};
