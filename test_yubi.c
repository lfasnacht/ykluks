
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

//Yubikey
#include <ykpers.h>
#include <yubikey.h>
#include <ykdef.h>

#define YK_SLOT 2




/**
 * Convert binary data to ASCII encoding using Crockford Base32 encoding.
 * Does not append 0-terminator, but returns a pointer to the place where
 * it should be placed, if needed.
 *
 * @param data data to encode
 * @param size size of data (in bytes)
 * @param out buffer to fill
 * @param out_size size of the buffer. Must be large enough to hold
 * ((size*8) + (((size*8) % 5) > 0 ? 5 - ((size*8) % 5) : 0)) / 5 bytes
 * @return pointer to the next byte in 'out' or NULL on error.
 */
char *
data_to_string (const void *data, size_t size, char *out, size_t out_size)
{
  /**
   * 32 characters for encoding
   */
  static char *encTable__ = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  unsigned int wpos;
  unsigned int rpos;
  unsigned int bits;
  unsigned int vbit;
  const unsigned char *udata;

  /* GNUNET_assert (data != NULL); */
  /* GNUNET_assert (out != NULL); */
  udata = data;
  if (out_size < (((size*8) + ((size*8) % 5)) % 5))
  {
    //GNUNET_break (0);
    return NULL;
  }
  vbit = 0;
  wpos = 0;
  rpos = 0;
  bits = 0;
  while ((rpos < size) || (vbit > 0))
  {
    if ((rpos < size) && (vbit < 5))
    {
      bits = (bits << 8) | udata[rpos++];   /* eat 8 more bits */
      vbit += 8;
    }
    if (vbit < 5)
    {
      bits <<= (5 - vbit);      /* zero-padding */
      //GNUNET_assert (vbit == ((size * 8) % 5));
      vbit = 5;
    }
    if (wpos >= out_size)
    {
      //GNUNET_break (0);
      return NULL;
    }
    out[wpos++] = encTable__[(bits >> (vbit - 5)) & 31];
    vbit -= 5;
  }
  //GNUNET_assert (vbit == 0);
  if (wpos < out_size)
    out[wpos] = '\0';
  return &out[wpos];
}


int
main(int argc, const char* argv[])
{
  YK_KEY *yk = NULL;
  const unsigned char *challenge = "Hello";
  unsigned char response[SHA1_MAX_BLOCK_SIZE];
  unsigned int bytes_read;
  unsigned char enc[(SHA1_MAX_BLOCK_SIZE * 2) + 1];
  unsigned int expect_bytes = 20;

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
  yubikey_hex_encode (enc, response, SHA1_MAX_BLOCK_SIZE);
  (void) printf ("Response: %s\n", enc);
  challenge="test";
  if (!yk_challenge_response (yk,
                              SLOT_CHAL_HMAC2,
                              1,
                              strlen(challenge), challenge,
                              sizeof(response), response))
    return 6;
  (void) memset (enc, sizeof(enc), 0);
  yubikey_hex_encode (enc, response, SHA1_MAX_BLOCK_SIZE);
  (void) printf ("Respons2: %s\n", enc);
  if (!yk_close_key (yk))
    return 2;
  if (!yk_release())
    return 1;
  return 0;
}
