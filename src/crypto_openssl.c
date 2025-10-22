/*
** SQLCipher
** http://sqlcipher.net
**
** Copyright (c) 2008 - 2013, ZETETIC LLC
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are met:
**     * Redistributions of source code must retain the above copyright
**       notice, this list of conditions and the following disclaimer.
**     * Redistributions in binary form must reproduce the above copyright
**       notice, this list of conditions and the following disclaimer in the
**       documentation and/or other materials provided with the distribution.
**     * Neither the name of the ZETETIC LLC nor the
**       names of its contributors may be used to endorse or promote products
**       derived from this software without specific prior written permission.
**
** THIS SOFTWARE IS PROVIDED BY ZETETIC LLC ''AS IS'' AND ANY
** EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
** WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL ZETETIC LLC BE LIABLE FOR ANY
** DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
** (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
** LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
** ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
** SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**
*/
/* BEGIN SQLCIPHER */
#ifdef SQLITE_HAS_CODEC
#ifdef SQLCIPHER_CRYPTO_OPENSSL
#include "sqliteInt.h"
#include "sqlcipher.h"
#include <openssl/crypto.h> /* amalgamator: dontcache */
#include <openssl/rand.h> /* amalgamator: dontcache */
#include <openssl/evp.h> /* amalgamator: dontcache */
#include <openssl/objects.h> /* amalgamator: dontcache */
#include <openssl/hmac.h> /* amalgamator: dontcache */
#include <openssl/err.h> /* amalgamator: dontcache */
#include <openssl/kdf.h> /* amalgamator: dontcache */
#include <openssl/params.h> /* amalgamator: dontcache */
#include <openssl/core_names.h> /* amalgamator: dontcache */

/*
 * This is a reference implementation of the sqlcipher_provider interface
 * for OpenSSL. It is intended to be absolutely minimal, i.e.  small,
 * simple, easily auditable, and infrequently changed. This makes it a
 * good starting place for anyone writing their own provider. Note that this
 * implementation is intentionally non-optimized and raw performance
 * is deliberately not a goal for this file. Please don't send patches/PRs or
 * open issues proposing performance changes to this file.
 *
 * If your use case requires a faster or more heavily optimized provider
 * you are welcome and encouraged to write one using this as a template and
 * referring to the sqlcipher_provider definition in sqlcipher.h. At compile time,
 * set it as the default provider with SQLCIPHER_CRYPTO_CUSTOM and supply
 * the provider source using EXTRA_SRC.
 */

static void sqlcipher_openssl_log_errors() {
    unsigned long err = 0;
    while((err = ERR_get_error()) != 0) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: ERR_get_error() returned %lx: %s", __func__, err, ERR_error_string(err, NULL));
    }
}

static int sqlcipher_openssl_add_random(void *ctx, const void *buffer, int length) {
#ifndef SQLCIPHER_OPENSSL_NO_MUTEX_RAND
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entering SQLCIPHER_MUTEX_PROVIDER_RAND", __func__);
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_RAND));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entered SQLCIPHER_MUTEX_PROVIDER_RAND", __func__);
#endif
  RAND_add(buffer, length, 0);
#ifndef SQLCIPHER_OPENSSL_NO_MUTEX_RAND
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: leaving SQLCIPHER_MUTEX_PROVIDER_RAND", __func__);
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_RAND));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: left SQLCIPHER_MUTEX_PROVIDER_RAND", __func__);
#endif
  return SQLITE_OK;
}

#define OPENSSL_CIPHER EVP_aes_256_cbc()

static int sqlcipher_openssl_activate(void *ctx) {
  return SQLITE_OK;
}

static int sqlcipher_openssl_deactivate(void *ctx) {
  return SQLITE_OK;
}

static const char* sqlcipher_openssl_get_provider_name(void *ctx) {
  return "openssl";
}

static const char* sqlcipher_openssl_get_provider_version(void *ctx) {
  return OpenSSL_version(OPENSSL_VERSION);
}

/* generate a defined number of random bytes */
static int sqlcipher_openssl_random (void *ctx, void *buffer, int length) {
  int rc = 0;
  /* concurrent calls to RAND_bytes can cause a crash under some openssl versions when a 
     naive application doesn't use CRYPTO_set_locking_callback and
     CRYPTO_THREADID_set_callback to ensure openssl thread safety. 
     This is simple workaround to prevent this common crash
     but a more proper solution is that applications setup platform-appropriate
     thread saftey in openssl externally */
#ifndef SQLCIPHER_OPENSSL_NO_MUTEX_RAND
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entering SQLCIPHER_MUTEX_PROVIDER_RAND", __func__);
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_RAND));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entered SQLCIPHER_MUTEX_PROVIDER_RAND", __func__);
#endif
  rc = RAND_bytes((unsigned char *)buffer, length);
#ifndef SQLCIPHER_OPENSSL_NO_MUTEX_RAND
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: leaving SQLCIPHER_MUTEX_PROVIDER_RAND", __func__);
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_RAND));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: left SQLCIPHER_MUTEX_PROVIDER_RAND", __func__);
#endif
  if(rc != 1) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: RAND_bytes() returned %d", __func__, rc);
    sqlcipher_openssl_log_errors();
    return SQLITE_ERROR;
  }
  return SQLITE_OK;
}

static int sqlcipher_openssl_hmac(
  void *ctx, int algorithm,
  const unsigned char *hmac_key, int key_sz,
  const unsigned char *in, int in_sz,
  const unsigned char *in2, int in2_sz,
  unsigned char *out
) {
  int rc = 0;

  size_t outlen;
  EVP_MAC *mac = NULL;
  EVP_MAC_CTX *hctx = NULL;
  OSSL_PARAM sha1[] = { { "digest", OSSL_PARAM_UTF8_STRING, "sha1", 4, 0 }, OSSL_PARAM_END };
  OSSL_PARAM sha256[] = { { "digest", OSSL_PARAM_UTF8_STRING, "sha256", 6, 0 }, OSSL_PARAM_END };
  OSSL_PARAM sha512[] = { { "digest", OSSL_PARAM_UTF8_STRING, "sha512", 6, 0 }, OSSL_PARAM_END };

  if(in == NULL) goto error;

  mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
  if(mac == NULL) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: EVP_MAC_fetch for HMAC failed", __func__);
    sqlcipher_openssl_log_errors();
    goto error;
  }

  hctx = EVP_MAC_CTX_new(mac);
  if(hctx == NULL) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: EVP_MAC_CTX_new() failed", __func__);
    sqlcipher_openssl_log_errors();
    goto error;
  }

  switch(algorithm) {
    case SQLCIPHER_HMAC_SHA1:
      if(!(rc = EVP_MAC_init(hctx, hmac_key, key_sz, sha1))) {
        sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: EVP_MAC_init() with key size %d and sha1 returned %d", __func__, key_sz, rc);
        sqlcipher_openssl_log_errors();
        goto error;
      }
      break;
    case SQLCIPHER_HMAC_SHA256:
      if(!(rc = EVP_MAC_init(hctx, hmac_key, key_sz, sha256))) {
        sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: EVP_MAC_init() with key size %d and sha256 returned %d", __func__, key_sz, rc);
        sqlcipher_openssl_log_errors();
        goto error;
      }
      break;
    case SQLCIPHER_HMAC_SHA512:
      if(!(rc = EVP_MAC_init(hctx, hmac_key, key_sz, sha512))) {
        sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: EVP_MAC_init() with key size %d and sha512 returned %d", __func__, key_sz, rc);
        sqlcipher_openssl_log_errors();
        goto error;
      }
      break;
    default:
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: invalid algorithm %d", __func__, algorithm);
      goto error;
  }

  if(!(rc = EVP_MAC_update(hctx, in, in_sz))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: EVP_MAC_update() on 1st input buffer of %d bytes using algorithm %d returned %d", __func__, in_sz, algorithm, rc);
    sqlcipher_openssl_log_errors();
    goto error;
  }

  if(in2 != NULL) {
    if(!(rc = EVP_MAC_update(hctx, in2, in2_sz))) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: EVP_MAC_update() on 2nd input buffer of %d bytes using algorithm %d returned %d", __func__, in_sz, algorithm, rc);
      sqlcipher_openssl_log_errors();
      goto error;
    }
  }

  if(!(rc = EVP_MAC_final(hctx, NULL, &outlen, 0))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: 1st EVP_MAC_final() for output length calculation using algorithm %d returned %d", __func__, algorithm, rc);
    sqlcipher_openssl_log_errors();
    goto error;
  }

  if(!(rc = EVP_MAC_final(hctx, out, &outlen, outlen))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: 2nd EVP_MAC_final() using algorithm %d returned %d", __func__, algorithm, rc);
    sqlcipher_openssl_log_errors();
    goto error;
  }

  rc = SQLITE_OK;
  goto cleanup;

error:
  rc = SQLITE_ERROR;

cleanup:
  if(hctx) EVP_MAC_CTX_free(hctx);
  if(mac) EVP_MAC_free(mac);

  return rc;
}

static int sqlcipher_openssl_kdf(
  void *ctx, int algorithm,
  const unsigned char *pass, int pass_sz,
  const unsigned char* salt, int salt_sz,
  int workfactor,
  int key_sz, unsigned char *key
) {
  int rc = 0;

  switch(algorithm) {
    case SQLCIPHER_PBKDF2_HMAC_SHA1:
      if(!(rc = PKCS5_PBKDF2_HMAC((const char *)pass, pass_sz, salt, salt_sz, workfactor, EVP_sha1(), key_sz, key))) {
        sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: PKCS5_PBKDF2_HMAC() for EVP_sha1() workfactor %d and key size %d returned %d", __func__, workfactor, key_sz, rc);
        sqlcipher_openssl_log_errors();
        goto error;
      }
      break;
    case SQLCIPHER_PBKDF2_HMAC_SHA256:
      if(!(rc = PKCS5_PBKDF2_HMAC((const char *)pass, pass_sz, salt, salt_sz, workfactor, EVP_sha256(), key_sz, key))) {
        sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: PKCS5_PBKDF2_HMAC() for EVP_sha256() workfactor %d and key size %d returned %d", __func__, workfactor, key_sz, rc);
        sqlcipher_openssl_log_errors();
        goto error;
      }
      break;
    case SQLCIPHER_PBKDF2_HMAC_SHA512:
      if(!(rc = PKCS5_PBKDF2_HMAC((const char *)pass, pass_sz, salt, salt_sz, workfactor, EVP_sha512(), key_sz, key))) {
        sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: PKCS5_PBKDF2_HMAC() for EVP_sha512() workfactor %d and key size %d returned %d", __func__, workfactor, key_sz, rc);
        sqlcipher_openssl_log_errors();
        goto error;
      }
      break;
    default:
      return SQLITE_ERROR;
  }

  rc = SQLITE_OK;
  goto cleanup;
error:
  rc = SQLITE_ERROR;
cleanup:
  return rc;
}

static int sqlcipher_openssl_cipher(
  void *ctx, int mode,
  const unsigned char *key, int key_sz,
  const unsigned char *iv,
  const unsigned char *in, int in_sz,
  unsigned char *out
) {
  int tmp_csz, csz, rc = 0;
  EVP_CIPHER_CTX* ectx = EVP_CIPHER_CTX_new();
  if(ectx == NULL) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: EVP_CIPHER_CTX_new failed", __func__);
    sqlcipher_openssl_log_errors();
    goto error;
  }

  if(!(rc = EVP_CipherInit_ex(ectx, OPENSSL_CIPHER, NULL, NULL, NULL, mode))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: EVP_CipherInit_ex for mode %d returned %d", __func__, mode, rc);
    sqlcipher_openssl_log_errors();
    goto error;
  }

  if(!(rc = EVP_CIPHER_CTX_set_padding(ectx, 0))) { /* no padding */
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: EVP_CIPHER_CTX_set_padding 0 returned %d", __func__, rc);
    sqlcipher_openssl_log_errors();
    goto error;
  }

  if(!(rc = EVP_CipherInit_ex(ectx, NULL, NULL, key, iv, mode))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: EVP_CipherInit_ex for mode %d returned %d", __func__, mode, rc);
    sqlcipher_openssl_log_errors();
    goto error;
  }

  if(!(rc = EVP_CipherUpdate(ectx, out, &tmp_csz, in, in_sz))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: EVP_CipherUpdate returned %d", __func__, rc);
    sqlcipher_openssl_log_errors();
    goto error;
  }

  csz = tmp_csz;  
  out += tmp_csz;
  if(!(rc = EVP_CipherFinal_ex(ectx, out, &tmp_csz))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: EVP_CipherFinal_ex returned %d", __func__, rc);
    sqlcipher_openssl_log_errors();
    goto error;
  }

  csz += tmp_csz;
  assert(in_sz == csz);

  rc = SQLITE_OK;
  goto cleanup;
error:
  rc = SQLITE_ERROR;
cleanup:
  if(ectx) EVP_CIPHER_CTX_free(ectx);
  return rc; 
}

static const char* sqlcipher_openssl_get_cipher(void *ctx) {
  return EVP_CIPHER_get0_name(OPENSSL_CIPHER);
}

static int sqlcipher_openssl_get_key_sz(void *ctx) {
  return EVP_CIPHER_key_length(OPENSSL_CIPHER);
}

static int sqlcipher_openssl_get_iv_sz(void *ctx) {
  return EVP_CIPHER_iv_length(OPENSSL_CIPHER);
}

static int sqlcipher_openssl_get_block_sz(void *ctx) {
  return EVP_CIPHER_block_size(OPENSSL_CIPHER);
}

static int sqlcipher_openssl_get_hmac_sz(void *ctx, int algorithm) {
  switch(algorithm) {
    case SQLCIPHER_HMAC_SHA1:
      return EVP_MD_size(EVP_sha1());
      break;
    case SQLCIPHER_HMAC_SHA256:
      return EVP_MD_size(EVP_sha256());
      break;
    case SQLCIPHER_HMAC_SHA512:
      return EVP_MD_size(EVP_sha512());
      break;
    default:
      return 0;
  }
}

static int sqlcipher_openssl_ctx_init(void **ctx) {
  return sqlcipher_openssl_activate(*ctx);
}

static int sqlcipher_openssl_ctx_free(void **ctx) {
  return sqlcipher_openssl_deactivate(NULL);
}

static int sqlcipher_openssl_fips_status(void *ctx) {
  return 0;
}

#define OPENSSL_AEAD_CIPHER EVP_aes_256_gcm()
#define OPENSSL_AEAD_IV_SZ 12
#define OPENSSL_AEAD_TAG_SZ 16


/* SQLCipher's AEAD implementation uses counter based  key-based key derivation to
 * generate a key for each page from the provided key material.
 * This function implements a SP 800-108 counter mode KDF using AES-256-CMAC
 * modeled after XAES-256-GCM. Specifically it uses a 16 bit counter size, 'x' label,
 * a 96 bit context, and omits the L field because the output is a fixed size. 
 * see:
 *   https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-upd1.pdf
 *   https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md
 */
static int sqlcipher_openssl_aead_kbkdf(
  void *ctx,
  const unsigned char *key, int key_sz,
  const unsigned char *context, int context_sz,
  unsigned char *out
){
  int rc = 0;
  unsigned char label = 0x58;
  EVP_KDF *kdf = NULL;
  EVP_KDF_CTX *kctx = NULL;
  int r = 16, use_l = 0;

  OSSL_PARAM params[] = {
    OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC, "CMAC", 0), 
    OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, "COUNTER", 0), 
    OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CIPHER, "AES-256-CBC", 0),
    OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)key, key_sz),
    OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, &label, sizeof(label)),
    OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)context, context_sz),
    OSSL_PARAM_construct_int(OSSL_KDF_PARAM_KBKDF_R, &r), /* 16 bit (2 byte) counter */
    OSSL_PARAM_construct_int(OSSL_KDF_PARAM_KBKDF_USE_L, &use_l), /* omit L (output lenght) because it is fixed size */
    OSSL_PARAM_construct_end()
  };

  if(!(kdf = EVP_KDF_fetch(NULL, "KBKDF", NULL))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: EVP_KDF_fetch failed", __func__);
    sqlcipher_openssl_log_errors();
    goto error;
  }

  if(!(kctx = EVP_KDF_CTX_new(kdf))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: EVP_KDF_CTX_new failed", __func__);
    sqlcipher_openssl_log_errors();
    goto error;
  }

  if(!(rc = EVP_KDF_derive(kctx, out, key_sz, params))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: EVP_KDF_derive failed %d", __func__, rc);
    sqlcipher_openssl_log_errors();
    goto error;
  }

  rc = SQLITE_OK;
  goto cleanup;

error:
  rc = SQLITE_ERROR;

cleanup:
  if(kctx) EVP_KDF_CTX_free(kctx);
  if(kdf) EVP_KDF_free(kdf);
  return rc;
}

static int sqlcipher_openssl_aead_cipher(
  void *ctx, int mode,
  const unsigned char *key, int key_sz,
  const unsigned char *iv,
  const unsigned char *aad, int aad_sz,
  const unsigned char *in, int in_sz,
  unsigned char *tag,
  unsigned char *out) {

  int tmp_csz, csz, rc = 0;

  EVP_CIPHER_CTX* ectx = EVP_CIPHER_CTX_new();
  if(ectx == NULL) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: EVP_CIPHER_CTX_new failed", __func__);
    sqlcipher_openssl_log_errors();
    goto error;
  }

  if(!(rc = EVP_CipherInit_ex(ectx, OPENSSL_AEAD_CIPHER, NULL, NULL, NULL, mode))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: EVP_CipherInit_ex for mode %d returned %d", __func__, mode, rc);
    sqlcipher_openssl_log_errors();
    goto error;
  }

  if(!(rc = EVP_CIPHER_CTX_set_padding(ectx, 0))) { /* no padding */
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: EVP_CIPHER_CTX_set_padding 0 returned %d", __func__, rc);
    sqlcipher_openssl_log_errors();
    goto error;
  }

  if(!(rc = EVP_CipherInit_ex(ectx, NULL, NULL, key, iv, mode))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: EVP_CipherInit_ex for mode %d returned %d", __func__, mode, rc);
    sqlcipher_openssl_log_errors();
    goto error;
  }

  /* provide AAD data (pageno) */
  if(!(rc = EVP_CipherUpdate(ectx, NULL, &tmp_csz, aad, aad_sz))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: EVP_CipherUpdate for AAD returned %d", __func__, rc);
    sqlcipher_openssl_log_errors();
    goto error;
  }

  if(!(rc = EVP_CipherUpdate(ectx, out, &tmp_csz, in, in_sz))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: EVP_CipherUpdate returned %d", __func__, rc);
    sqlcipher_openssl_log_errors();
    goto error;
  }

  csz = tmp_csz;  
  out += tmp_csz;

  if(mode == SQLCIPHER_DECRYPT) {
    if(!(rc = EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_SET_TAG, 16, tag))) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: EVP_CPHER_CTX_ctrl failed to set tag %d", __func__, rc);
      sqlcipher_openssl_log_errors();
      goto error;
    }
  }

  if(!(rc = EVP_CipherFinal_ex(ectx, out, &tmp_csz))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: EVP_CipherFinal_ex returned %d", __func__, rc);
    sqlcipher_openssl_log_errors();
    goto error;
  }

  csz += tmp_csz;
  assert(in_sz == csz);
 
  if(mode == SQLCIPHER_ENCRYPT) {
    if(!(rc = EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_GET_TAG, 16, tag))) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: EVP_CPHER_CTX_ctrl failed to get tag %d", __func__, rc);
      sqlcipher_openssl_log_errors();
      goto error;
    }
  }

  rc = SQLITE_OK;
  goto cleanup;
error:
  rc = SQLITE_ERROR;
cleanup:
  if(ectx) EVP_CIPHER_CTX_free(ectx);
  return rc; 
}

static int sqlcipher_openssl_get_aead_iv_sz(void *ctx) {
  return OPENSSL_AEAD_IV_SZ;
}

static int sqlcipher_openssl_get_aead_tag_sz(void *ctx) {
  return OPENSSL_AEAD_TAG_SZ;
}

static const char* sqlcipher_openssl_get_aead_cipher(void *ctx) {
  return EVP_CIPHER_get0_name(OPENSSL_AEAD_CIPHER);
}

/* SQLCipher's v5 construct is similar to XAES-256-GCM split across two separate KDF and GCM operations. We can
 * self-test proper operation using the official KAT:
 *   https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md
 * This test runs the input key and first 96 bits of the 192 bit IV through the KDF function, then 
 * uses the output key with AES-256-GCM and the second 96 bits as the GCM IV. */
static int sqlcipher_openssl_self_test(void *ctx) {
  int rc;

  unsigned char K[32] = {
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
  };

  unsigned char Kx[32] = {
    0xc8, 0x61, 0x2c, 0x9e, 0xd5, 0x3f, 0xe4, 0x3e,
    0x8e, 0x00, 0x5b, 0x82, 0x8a, 0x16, 0x31, 0xa0,
    0xbb, 0xcb, 0x6a, 0xb2, 0xf4, 0x65, 0x14, 0xec,
    0x4f, 0x43, 0x9f, 0xcf, 0xd0, 0xfa, 0x96, 0x9b
  };

  /* ASCII "ABCDEFGHIJKLMNOPQRSTUVWX" where first 12 is KBKDF context, next 12 is GCM IV */
  unsigned char N[24] = {
      0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
      0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
      0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58
  };

  /* ASCII "XAES-256-GCM" */
  unsigned char PT[12] = {
    0x58, 0x41, 0x45, 0x53, 0x2d, 0x32, 0x35, 0x36,
    0x2d, 0x47, 0x43, 0x4d
  };

  const unsigned char CT[28] = {
    0xce, 0x54, 0x6e, 0xf6, 0x3c, 0x9c, 0xc6, 0x07,
    0x65, 0x92, 0x36, 0x09, 0xb3, 0x3a, 0x9a, 0x19,
    0x74, 0xe9, 0x6e, 0x52, 0xda, 0xf2, 0xfc, 0xf7,
    0x07, 0x5e, 0x22, 0x71
  };

  unsigned char Kx_out[32];
  unsigned char CT_out[28];
 
  if((rc = sqlcipher_openssl_aead_kbkdf(
    ctx,
    K, sizeof(K),
    N, sizeof(N) / 2,
    Kx_out
  )) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: kbkdf failed %d", __func__, rc);
    return rc;
  }
            
  if((rc = sqlcipher_openssl_aead_cipher(
      ctx, SQLCIPHER_ENCRYPT,
      Kx_out, sizeof(Kx_out),
      N + (sizeof(N)/2),
      NULL, 0, /* No AEAD for this test */
      PT, sizeof(PT),
      CT_out + sizeof(PT), /* 16 byte tag goes at the end */
      CT_out
    )) != SQLITE_OK
  ) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: aead_cipher failed %d", __func__, rc);
    return rc;
  } 

  if(memcmp(Kx, Kx_out, sizeof(Kx)) != 0) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: KAT subkey mismatch", __func__);
    return SQLITE_ERROR;
  }

  if(memcmp(CT, CT_out, sizeof(CT)) != 0) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: KAT ciphertext mismatch", __func__);
    return SQLITE_ERROR;
  }

  return SQLITE_OK;
}

int sqlcipher_openssl_setup(sqlcipher_provider *p) {
  p->init = NULL;
  p->shutdown = NULL;
  p->get_provider_name = sqlcipher_openssl_get_provider_name;
  p->random = sqlcipher_openssl_random;
  p->hmac = sqlcipher_openssl_hmac;
  p->kdf = sqlcipher_openssl_kdf;
  p->cipher = sqlcipher_openssl_cipher;
  p->get_cipher = sqlcipher_openssl_get_cipher;
  p->get_key_sz = sqlcipher_openssl_get_key_sz;
  p->get_iv_sz = sqlcipher_openssl_get_iv_sz;
  p->get_block_sz = sqlcipher_openssl_get_block_sz;
  p->get_hmac_sz = sqlcipher_openssl_get_hmac_sz;
  p->ctx_init = sqlcipher_openssl_ctx_init;
  p->ctx_free = sqlcipher_openssl_ctx_free;
  p->add_random = sqlcipher_openssl_add_random;
  p->fips_status = sqlcipher_openssl_fips_status;
  p->get_provider_version = sqlcipher_openssl_get_provider_version;
  p->aead_kbkdf = sqlcipher_openssl_aead_kbkdf;
  p->aead_cipher = sqlcipher_openssl_aead_cipher;
  p->get_aead_iv_sz = sqlcipher_openssl_get_aead_iv_sz;
  p->get_aead_tag_sz = sqlcipher_openssl_get_aead_tag_sz;
  p->get_aead_cipher = sqlcipher_openssl_get_aead_cipher;
  p->self_test = sqlcipher_openssl_self_test;
  return SQLITE_OK;
}

#endif
#endif
/* END SQLCIPHER */
