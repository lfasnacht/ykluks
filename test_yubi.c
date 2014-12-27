
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#define GCRYPT_NO_MPI_MACROS 1
#define GCRYPT_NO_DEPRECATED 1
#include <gcrypt.h>

//Yubikey
#include <ykpers.h>
#include <yubikey.h>
#include <ykdef.h>

#define YK_SLOT 2

#define KDF_KEY_SIZE 40

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by gcry_strerror(rc).
 */
#define LOG_GCRY(cmd, rc) do { fprintf(stderr, "`%s' failed at %s:%d with error: %s\n", cmd, __FILE__, __LINE__, gcry_strerror(rc)); } while(0)

int
main(int argc, const char* argv[])
{
  YK_KEY *yk = NULL;
  const unsigned char *challenge = "Hello";
  unsigned char response[SHA1_MAX_BLOCK_SIZE];
  unsigned int bytes_read;
  unsigned char enc[(SHA1_MAX_BLOCK_SIZE * 2) + 1];
  unsigned int expect_bytes = 20;
  const char *passphrase;
  unsigned char key[KDF_KEY_SIZE];
  gcry_error_t gerr;

  if (!gcry_check_version (GCRYPT_VERSION))
  {
    fputs("libgcrypt version mismatch\n", stderr);
    return 1;
  }
  /* Tell Libgcrypt that initialization has completed. */
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  passphrase = "password";
  if (0 != (gerr = gcry_kdf_derive (passphrase, strlen(passphrase),
                                    GCRY_KDF_PBKDF2,
                                    GCRY_MD_SHA1,
                                    (const void *) "salt", 4, /* salt & salt length */
                                    4, /* iterations */
                                    KDF_KEY_SIZE, key)))
  {
    LOG_GCRY ("gcry_kdf_derive", gerr);
    return 1;
  }
  (void) memset (enc, sizeof(enc), 0);
  yubikey_hex_encode (enc, key, KDF_KEY_SIZE);
  (void) printf ("Derived key: %s\n", enc);
  if (!yk_init())
    return 1;
  yk = yk_open_first_key ();
  if (NULL == yk)
    return 2;
  if (!yk_check_firmware_version(yk))
    return 3;
  if (!yk_write_to_key (yk, SLOT_CHAL_HMAC2, challenge, strlen (challenge)))
    return 4;
  (void) memset(response, sizeof(response), 0);
  if (!yk_read_response_from_key (yk, YK_SLOT,
                                  YK_FLAG_MAYBLOCK,
                                  response, sizeof(response),
                                  expect_bytes,
                                  &bytes_read))
    return 5;
  (void) memset (enc, sizeof(enc), 0);
  yubikey_hex_encode (enc, response, expect_bytes);
  (void) printf ("Response: %s\n", enc);
  if (!yk_challenge_response (yk,
                              SLOT_CHAL_HMAC2,
                              1,
                              strlen(challenge), challenge,
                              sizeof(response), response))
    return 6;
  (void) memset (enc, sizeof(enc), 0);
  yubikey_hex_encode (enc, response, expect_bytes);
  (void) printf ("Respons2: %s\n", enc);
  if (!yk_close_key (yk))
    return 2;
  if (!yk_release())
    return 1;
  return 0;
}
