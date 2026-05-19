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
#if !defined(OMIT_SQLCIPHER)
#ifdef SQLCIPHER_CRYPTO_LIBTOMCRYPT
#include "sqliteInt.h"
#include "sqlcipher.h"
#include <tomcrypt.h>

/*
 * This is a reference implementation of the sqlcipher_provider interface
 * for LibTomCrypt. It is intended to be absolutely minimal, i.e.  small,
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


#define FORTUNA_MAX_SZ 32
static prng_state prng;
static volatile unsigned int ltc_init = 0;
static volatile unsigned int ltc_ref_count = 0;

#define LTC_CIPHER "aes"

static int sqlcipher_ltc_add_random(void *ctx, const void *buffer, int length) {
  int rc = 0;
  int data_to_read = length;
  int block_sz = data_to_read < FORTUNA_MAX_SZ ? data_to_read : FORTUNA_MAX_SZ;
  const unsigned char * data = (const unsigned char *)buffer;

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entering SQLCIPHER_MUTEX_PROVIDER_RAND", __func__);
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_RAND));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entered SQLCIPHER_MUTEX_PROVIDER_RAND", __func__);

  while(data_to_read > 0){
    if((rc = fortuna_add_entropy(data, block_sz, &prng)) != CRYPT_OK) break;
    data_to_read -= block_sz;
    data += block_sz;
    block_sz = data_to_read < FORTUNA_MAX_SZ ? data_to_read : FORTUNA_MAX_SZ;
  }

  if(rc == CRYPT_OK) {
    rc = fortuna_ready(&prng);
  }

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: leaving SQLCIPHER_MUTEX_PROVIDER_RAND", __func__);
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_RAND));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: left SQLCIPHER_MUTEX_PROVIDER_RAND", __func__);

  return rc == CRYPT_OK ? SQLITE_OK : SQLITE_ERROR;
}

static int sqlcipher_ltc_activate(void *ctx) {
  unsigned char random_buffer[FORTUNA_MAX_SZ];
  int bytes = 0;
  int rc = SQLITE_OK;

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entering SQLCIPHER_MUTEX_PROVIDER_ACTIVATE", __func__);
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_ACTIVATE));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entered SQLCIPHER_MUTEX_PROVIDER_ACTIVATE", __func__);

  sqlcipher_memset(random_buffer, 0, FORTUNA_MAX_SZ);
  if(ltc_init == 0) {
    if(register_prng(&fortuna_desc) < 0) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: failed to register fortuna", __func__);
      rc = SQLITE_ERROR;
      goto cleanup;
    }
    if(register_cipher(&aes_desc) < 0) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: failed to register aes", __func__);
      rc = SQLITE_ERROR;
      goto cleanup;
    }
    if(register_hash(&sha512_desc) < 0) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: failed to register sha512", __func__);
      rc = SQLITE_ERROR;
      goto cleanup;
    }
    if(register_hash(&sha256_desc) < 0) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: failed to register sha256", __func__);
      rc = SQLITE_ERROR;
      goto cleanup;
    }
    if(register_hash(&sha1_desc) < 0) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: failed to register sha1", __func__);
      rc = SQLITE_ERROR;
      goto cleanup;
    }
    if(fortuna_start(&prng) != CRYPT_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: failed to start fortuna", __func__);
      rc = SQLITE_ERROR;
      goto cleanup;
    }

    ltc_init = 1;
  }

  bytes = rng_get_bytes(random_buffer, FORTUNA_MAX_SZ, NULL);

  if(bytes != FORTUNA_MAX_SZ) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: rng_get_bytes returned insufficient bytes %d of %d requested", __func__, bytes, FORTUNA_MAX_SZ);
    rc = SQLITE_ERROR;
    goto cleanup;
  }

  if((rc = sqlcipher_ltc_add_random(ctx, random_buffer, FORTUNA_MAX_SZ)) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: failed to add random: %d", __func__, rc);
    goto cleanup;
  }
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_PROVIDER, "%s: seeded fortuna with %d bytes from rng_get_bytes", __func__, FORTUNA_MAX_SZ);

  ltc_ref_count++;

cleanup:
  sqlcipher_memset(random_buffer, 0, FORTUNA_MAX_SZ);

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: leaving SQLCIPHER_MUTEX_PROVIDER_ACTIVATE", __func__);
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_ACTIVATE));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: left SQLCIPHER_MUTEX_PROVIDER_ACTIVATE", __func__);

  return rc;
}

static int sqlcipher_ltc_deactivate(void *ctx) {
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entering SQLCIPHER_MUTEX_PROVIDER_ACTIVATE", __func__);
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_ACTIVATE));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entered SQLCIPHER_MUTEX_PROVIDER_ACTIVATE", __func__);

  if(ltc_ref_count > 0) ltc_ref_count--;

  if(ltc_ref_count == 0){
    fortuna_done(&prng);
    sqlcipher_memset((void *)&prng, 0, sizeof(prng));
    ltc_init = 0; /* clear ltc_init so fortuna will be restarted */
  }

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: leaving SQLCIPHER_MUTEX_PROVIDER_ACTIVATE", __func__);
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_ACTIVATE));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: left SQLCIPHER_MUTEX_PROVIDER_ACTIVATE", __func__);

  return SQLITE_OK;
}

static const char* sqlcipher_ltc_get_provider_name(void *ctx) {
  return "libtomcrypt";
}

static const char* sqlcipher_ltc_get_provider_version(void *ctx) {
  return SCRYPT;
}

static int sqlcipher_ltc_random(void *ctx, void *buffer, int length) {
  int rc = SQLITE_OK;
  int bytes = 0;

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entering SQLCIPHER_MUTEX_PROVIDER_RAND", __func__);
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_RAND));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: entered SQLCIPHER_MUTEX_PROVIDER_RAND", __func__);

  if(length < 0 || (bytes = fortuna_read(buffer, length, &prng)) != length) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: fortuna_read returned insufficient bytes %d of %d requested", __func__, bytes, length);
    rc = SQLITE_ERROR;
  }

  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: leaving SQLCIPHER_MUTEX_PROVIDER_RAND", __func__);
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_RAND));
  sqlcipher_log(SQLCIPHER_LOG_TRACE, SQLCIPHER_LOG_MUTEX, "%s: left SQLCIPHER_MUTEX_PROVIDER_RAND", __func__);

  return rc;
}

static int sqlcipher_ltc_hmac(
  void *ctx, int algorithm,
  const unsigned char *hmac_key, int key_sz,
  const unsigned char *in, int in_sz,
  const unsigned char *in2, int in2_sz,
  unsigned char *out
) {
  int rc, hash_idx;
  unsigned long outlen;
  hmac_state hmac;

  if(in == NULL) goto error;

  switch(algorithm) {
    case SQLCIPHER_HMAC_SHA1:
      hash_idx = find_hash("sha1");
      break;
    case SQLCIPHER_HMAC_SHA256:
      hash_idx = find_hash("sha256");
      break;
    case SQLCIPHER_HMAC_SHA512:
      hash_idx = find_hash("sha512");
      break;
    default:
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: unsupported hmac algorithm", __func__);
      goto error;
  }

  if(hash_idx < 0) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: failed find_hash lookup", __func__);
    goto error;
  }

  outlen = hash_descriptor[hash_idx].hashsize;

  if((rc = hmac_init(&hmac, hash_idx, hmac_key, key_sz)) != CRYPT_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: hmac_init failed %d", __func__, rc);
    goto error;
  }
  if((rc = hmac_process(&hmac, in, in_sz)) != CRYPT_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: hmac_process failed %d", __func__, rc);
    goto error;
  }
  if(in2 != NULL && (rc = hmac_process(&hmac, in2, in2_sz)) != CRYPT_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: hmac_process 2 failed %d", __func__, rc);
    goto error;
  }
  if((rc = hmac_done(&hmac, out, &outlen)) != CRYPT_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: done failed %d", __func__, rc);
    goto error;
  }

  rc = SQLITE_OK;
  goto cleanup;

error:
  rc = SQLITE_ERROR;

cleanup:
  sqlcipher_memset(&hmac, 0, sizeof(hmac));
  return rc;
}

static int sqlcipher_ltc_kdf(
  void *ctx, int algorithm,
  const unsigned char *pass, int pass_sz,
  const unsigned char* salt, int salt_sz,
  int workfactor,
  int key_sz, unsigned char *key
) {
  int rc, hash_idx;
  unsigned long outlen = key_sz;

  switch(algorithm) {
    case SQLCIPHER_PBKDF2_HMAC_SHA1:
      hash_idx = find_hash("sha1");
      break;
    case SQLCIPHER_PBKDF2_HMAC_SHA256:
      hash_idx = find_hash("sha256");
      break;
    case SQLCIPHER_PBKDF2_HMAC_SHA512:
      hash_idx = find_hash("sha512");
      break;
    default:
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: unsupported hmac algorithm", __func__);
      return SQLITE_ERROR;
  }

  if(hash_idx < 0) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: failed find_hash lookup", __func__);
    return SQLITE_ERROR;
  }

  if((rc = pkcs_5_alg2(pass, pass_sz, salt, salt_sz,
                       workfactor, hash_idx, key, &outlen)) != CRYPT_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: failed pkc_5_alg2 %d", __func__, rc);
    return SQLITE_ERROR;
  }
  return SQLITE_OK;
}

static const char* sqlcipher_ltc_get_cipher(void *ctx) {
  return "aes-256-cbc";
}

static int sqlcipher_ltc_cipher(
  void *ctx, int mode,
  const unsigned char *key, int key_sz,
  const unsigned char *iv,
  const unsigned char *in, int in_sz,
  unsigned char *out
) {
  int rc, cipher_idx;
  symmetric_CBC cbc;

  if((cipher_idx = find_cipher(LTC_CIPHER)) == -1) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: failed find_cipher lookup", __func__);
    goto error;
  }
  if((rc = cbc_start(cipher_idx, iv, key, key_sz, 0, &cbc)) != CRYPT_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: failed cbc_start %d", __func__, rc);
    goto error;
  }
  if(mode == SQLCIPHER_ENCRYPT) {
    if((rc = cbc_encrypt(in, out, in_sz, &cbc)) != CRYPT_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: failed cbc_encrypt %d", __func__, rc);
      goto error;
    }
  } else {
    if((rc = cbc_decrypt(in, out, in_sz, &cbc)) != CRYPT_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: failed cbc_decrypt %d", __func__, rc);
      goto error;
    }
  }
  if((rc = cbc_done(&cbc)) != CRYPT_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: failed cbc_done %d", __func__, rc);
    goto error;
  }

  rc = SQLITE_OK;
  goto cleanup;

error:
  rc = SQLITE_ERROR;

cleanup:
  sqlcipher_memset(&cbc, 0, sizeof(cbc));
  return rc;
}

static int sqlcipher_ltc_get_key_sz(void *ctx) {
  int cipher_idx = find_cipher(LTC_CIPHER);
  if(cipher_idx < 0) return 0;
  return cipher_descriptor[cipher_idx].max_key_length;
}

static int sqlcipher_ltc_get_iv_sz(void *ctx) {
  int cipher_idx = find_cipher(LTC_CIPHER);
  if(cipher_idx < 0) return 0;
  return cipher_descriptor[cipher_idx].block_length;
}

static int sqlcipher_ltc_get_block_sz(void *ctx) {
  int cipher_idx = find_cipher(LTC_CIPHER);
  if(cipher_idx < 0) return 0;
  return cipher_descriptor[cipher_idx].block_length;
}

static int sqlcipher_ltc_get_hmac_sz(void *ctx, int algorithm) {
  int hash_idx;
  switch(algorithm) {
    case SQLCIPHER_HMAC_SHA1:
      hash_idx = find_hash("sha1");
      break;
    case SQLCIPHER_HMAC_SHA256:
      hash_idx = find_hash("sha256");
      break;
    case SQLCIPHER_HMAC_SHA512:
      hash_idx = find_hash("sha512");
      break;
    default:
      return 0;
  }

  if(hash_idx < 0) return 0;

  return hash_descriptor[hash_idx].hashsize;
}

static int sqlcipher_ltc_ctx_init(void **ctx) {
  return sqlcipher_ltc_activate(NULL);
}

static int sqlcipher_ltc_ctx_free(void **ctx) {
  return sqlcipher_ltc_deactivate(NULL);
}

static int sqlcipher_ltc_fips_status(void *ctx) {
  return 0;
}

#define LTC_AEAD_CIPHER "aes"
#define LTC_AEAD_IV_SZ 12
#define LTC_AEAD_TAG_SZ 16
#define LTC_AEAD_BLOCK_SZ 16

/* SQLCipher's AEAD implementation uses counter based key-based key derivation to
 * generate a key for each page from the provided key material.
 * This function implements a SP 800-108 counter mode KDF using AES-256-CMAC
 * modeled after XAES-256-GCM. Specifically it uses a 16 bit counter size, 'x' label,
 * a 96 bit context, and omits the L field because the output is a fixed size. 
 * see:
 *   https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-upd1.pdf
 *   https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md
 */
static int sqlcipher_ltc_aead_kbkdf(
  void *ctx,
  const unsigned char *key, int key_sz,
  const unsigned char *context, int context_sz,
  unsigned char *out
){
  int cipher_idx, i, rc = 0; 
  unsigned long out_sz = LTC_AEAD_BLOCK_SZ;
  omac_state *omac = NULL;
  
  /* SP 800-108 fixed fields */
  unsigned char label = 0x58;
  unsigned char separator = 0x00;
  unsigned char ii[4];
  int n = key_sz / 16;

  if((cipher_idx = find_cipher(LTC_AEAD_CIPHER)) == -1) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: find_cipher failed", __func__);
    return SQLITE_ERROR;
  }

  if(!(omac = sqlcipher_malloc(sizeof(omac_state)))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: failed to allocate omac_state", __func__);
    goto error;
  }
 
  for(i = 1; i <= n; i++) {
    sqlite3Put4byte(ii, i); /* iterator to big endian */
    if((rc = omac_init(omac, cipher_idx, key, key_sz)) != CRYPT_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: omac_init failed %d", __func__, rc);
      goto error;
    }

    if((rc = omac_process(omac, ii+2, 2)) != CRYPT_OK) { /* use 16 bit (2 byte) counter length */
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: omac_process(i) failed %d", __func__, rc);
      goto error;
    }
    if((rc = omac_process(omac, &label, sizeof(label))) != CRYPT_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: omac_process(label) failed %d", __func__, rc);
      goto error;
    }
    if((rc = omac_process(omac, &separator, sizeof(separator))) != CRYPT_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: omac_process(separator) failed %d", __func__, rc);
      goto error;
    }
    if((rc = omac_process(omac, context, context_sz)) != CRYPT_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: omac_process(context) failed %d", __func__, rc);
      goto error;
    }

    /* L parameter (output length) is be omitted entirely because the output lenght is fixed */

    if((rc = omac_done(omac, out + (i - 1) * LTC_AEAD_BLOCK_SZ, &out_sz)) != CRYPT_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: omac_done failed %d", __func__, rc);
      goto error;
    } 
  }

  rc = SQLITE_OK;
  goto cleanup;

error:
  rc = SQLITE_ERROR;
cleanup:
  if(omac) sqlcipher_free(omac, sizeof(omac_state));
  return rc;
}


static int sqlcipher_ltc_aead_cipher(
  void *ctx, int mode,
  const unsigned char *key, int key_sz,
  const unsigned char *iv,
  const unsigned char *aad, int aad_sz,
  const unsigned char *in, int in_sz,
  unsigned char *tag,
  unsigned char *out) {

  int rc, cipher_idx;
  unsigned char tag_out[LTC_AEAD_TAG_SZ];
  unsigned long tag_sz = LTC_AEAD_TAG_SZ;
  gcm_state *gcm = NULL;

  if((cipher_idx = find_cipher(LTC_AEAD_CIPHER)) == -1) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: find_cipher failed", __func__);
    return SQLITE_ERROR;
  }
  if(!(gcm = sqlcipher_malloc(sizeof(gcm_state)))) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: failed to allocate gcm_state", __func__);
    goto error;
  }
  if ((rc = gcm_init(gcm, cipher_idx, key, key_sz)) != CRYPT_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s gcm_init failed %d", __func__, rc);
    goto error;
  }
  if ((rc = gcm_add_iv(gcm, iv, LTC_AEAD_IV_SZ)) != CRYPT_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s gcm_add_iv failed %d", __func__, rc);
    goto error;
  }
  if ((rc = gcm_add_aad(gcm, aad, aad_sz)) != CRYPT_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s gcm_add_aad failed %d", __func__, rc);
    goto error;
  }
  if(mode == SQLCIPHER_ENCRYPT) {
    if ((rc = gcm_process(gcm, (unsigned char *)in, in_sz, out, GCM_ENCRYPT)) != CRYPT_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s gcm_process failed for encryption %d", __func__, rc);
      goto error;
    }
    if ((rc = gcm_done(gcm, tag, &tag_sz)) != CRYPT_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s gcm_done failed %d", __func__, rc);
      goto error;
    }
  } else {
    if ((rc = gcm_process(gcm, out, in_sz, (unsigned char *)in, GCM_DECRYPT)) != CRYPT_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s gcm_process failed for decryption %d", __func__, rc);
      goto error;
    }
    if ((rc = gcm_done(gcm, tag_out, &tag_sz)) != CRYPT_OK) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s gcm_done failed %d", __func__, rc);
      goto error;
    }
    /* perform manual tag verification, LTC does not do this internally in gcm_done */
    if(sqlcipher_memcmp(tag, tag_out, LTC_AEAD_TAG_SZ) != 0) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s gcm tag verification failed for decryption", __func__);
      goto error;
    }
  }

  rc = SQLITE_OK;
  goto cleanup;

error:
  rc = SQLITE_ERROR;

cleanup:
  sqlcipher_memset(tag_out, 0, LTC_AEAD_TAG_SZ);
  if(gcm) sqlcipher_free(gcm, sizeof(gcm_state));
  return rc;
}

static int sqlcipher_ltc_get_aead_iv_sz(void *ctx) {
  return LTC_AEAD_IV_SZ;
}

static int sqlcipher_ltc_get_aead_tag_sz(void *ctx) {
  return LTC_AEAD_TAG_SZ;
}

static const char* sqlcipher_ltc_get_aead_cipher(void *ctx) {
  return "aes-256-gcm";
}

/* SQLCipher's v5 construct is similar to XAES-256-GCM split across two separate KDF and GCM operations. We can
 * self-test proper operation using the official KAT:
 *   https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md
 * This test runs the input key and first 96 bits of the 192 bit IV through the KDF function, then 
 * uses the output key with AES-256-GCM and the second 96 bits as the GCM IV. */
static int sqlcipher_ltc_self_test(void *ctx) {
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
 
  if((rc = sqlcipher_ltc_aead_kbkdf(
    ctx,
    K, sizeof(K),
    N, sizeof(N) / 2,
    Kx_out
  )) != SQLITE_OK) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, SQLCIPHER_LOG_PROVIDER, "%s: kbkdf failed %d", __func__, rc);
    return rc;
  }
            
  if((rc = sqlcipher_ltc_aead_cipher(
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

int sqlcipher_ltc_setup(sqlcipher_provider *p) {
  p->init = NULL;
  p->shutdown = NULL;
  p->get_provider_name = sqlcipher_ltc_get_provider_name;
  p->random = sqlcipher_ltc_random;
  p->hmac = sqlcipher_ltc_hmac;
  p->kdf = sqlcipher_ltc_kdf;
  p->cipher = sqlcipher_ltc_cipher;
  p->get_cipher = sqlcipher_ltc_get_cipher;
  p->get_key_sz = sqlcipher_ltc_get_key_sz;
  p->get_iv_sz = sqlcipher_ltc_get_iv_sz;
  p->get_block_sz = sqlcipher_ltc_get_block_sz;
  p->get_hmac_sz = sqlcipher_ltc_get_hmac_sz;
  p->ctx_init = sqlcipher_ltc_ctx_init;
  p->ctx_free = sqlcipher_ltc_ctx_free;
  p->add_random = sqlcipher_ltc_add_random;
  p->fips_status = sqlcipher_ltc_fips_status;
  p->get_provider_version = sqlcipher_ltc_get_provider_version;
  p->aead_kbkdf = sqlcipher_ltc_aead_kbkdf;
  p->aead_cipher = sqlcipher_ltc_aead_cipher;
  p->get_aead_iv_sz = sqlcipher_ltc_get_aead_iv_sz;
  p->get_aead_tag_sz = sqlcipher_ltc_get_aead_tag_sz;
  p->get_aead_cipher = sqlcipher_ltc_get_aead_cipher;
  p->self_test = sqlcipher_ltc_self_test;
  return SQLITE_OK;
}

#endif
#endif
/* END SQLCIPHER */
