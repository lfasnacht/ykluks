/*
 * Copyright (c) 2012 Laurent Fasnacht
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 * 
 * This source code is based on:
 * 
 * - ykchalresp.c (ykpers, license: BSD-2)
 *    * Copyright (c) 2011-2012 Yubico AB.
 * 
 * - cryptsetup.c (cryptsetup, license: GPL-2)
 *    * Copyright (C) 2004, Christophe Saout <christophe@saout.de>
 *    * Copyright (C) 2004-2007, Clemens Fruhwirth <clemens@endorphin.org>
 *    * Copyright (C) 2009-2012, Red Hat, Inc. All rights reserved.
 * 
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

//Cryptsetup / LUKS
#include <libcryptsetup.h>

//Yubikey
#include <ykpers.h>
#include <yubikey.h>
#include <ykdef.h>

#define HASH_LENGTH 20
#define YK_SLOT 2
#define LUKS_KEY_SLOT 6
#define LUKS_CHALLENGE_KEY_SLOT_OFFSET 0x220
#define LUKS_FLAGS (CRYPT_ACTIVATE_ALLOW_DISCARDS)
#define LUKS_ITERATION_MS 1
#define WAIT_TIME 15

//Convention in this file: a function return 1 if successful, 0 otherwise
//Topics:
// - Yubikey
// - LUKS
// - Raw LUKS device access
// - Real algorithmic part

//Forward declarations:
int make_new_challenge(unsigned char *src, unsigned char *new_challenge);

//========= BEGIN YUBIKEY STUFF ========= 
//this is mostly based on ykchalresp.c
static void report_yk_error() {
  if (ykp_errno) {
    fprintf(stderr, "Yubikey personalization error: %s\n", ykp_strerror(ykp_errno));
  }
  if (yk_errno) {
    if (yk_errno == YK_EUSBERR) {
      fprintf(stderr, "USB error: %s\n", yk_usb_strerror());
    } else {
      fprintf(stderr, "Yubikey core error: %s\n", yk_strerror(yk_errno));
    }
  }
}

//Returns 1 if we have have a firmware version >= 2.2
int is_firmware_recent_enough(YK_KEY *yk) {
  int ret = 0;
  
  YK_STATUS *st = ykds_alloc();

  if (!yk_get_status(yk, st)) goto out;

  if (ykds_version_major(st) < 2 || (ykds_version_major(st) == 2 && ykds_version_minor(st) < 2)) {
    fprintf(stderr, "Challenge-response not supported before YubiKey 2.2.\n");
    goto out;
  }

  ret = 1;
out:
  free(st);
  return ret;
}

//Do a HMAC challenge-response on slot 2 for a HASH_LENGTH-byte challenge, and give a HASH_LENGTH-byte response
int challenge_response(YK_KEY *yk, unsigned char *challenge, unsigned char *response)
{
  unsigned char internal_response[64];
  unsigned int response_len = 0;

  memset(response, 0, sizeof(response));

  if (!yk_write_to_key(yk, SLOT_CHAL_HMAC2, challenge, HASH_LENGTH)) return 0;

  if (!yk_read_response_from_key(yk, YK_SLOT, YK_FLAG_MAYBLOCK, &internal_response, 64, HASH_LENGTH, &response_len))
    return 0;

  if (response_len > HASH_LENGTH) response_len = HASH_LENGTH;
  memcpy(response, internal_response, response_len);

  return 1;
}

//This creates the response, new_challenge, and new_response based on challenge and the yubikey
int yk_query(unsigned char *challenge, unsigned char *response, unsigned char *new_challenge, unsigned char *new_response) {
  YK_KEY *yk = 0;
  int ret = 0;
  time_t first_try = time(NULL);
  
  ykp_errno = 0;
  yk_errno = 0;

  if (!yk_init())                                           goto out;
  
  while (!(yk = yk_open_first_key()) && (time(NULL) - first_try <= WAIT_TIME)) {
    sleep(1);
  }
  
  if (!yk)                                                  goto out;
  if (!is_firmware_recent_enough(yk))                       goto out;
  if (!challenge_response(yk, challenge, response))         goto out;
  if (!make_new_challenge(response, new_challenge))         goto out;
  if (!challenge_response(yk, new_challenge, new_response)) goto out;
  
  ret = 1;
  
out:
  if (ret != 1) report_yk_error();

  if (yk && !yk_close_key(yk)) {
    report_yk_error();
    return 0;
  }

  if (!yk_release()) {
    report_yk_error();
    return 0;
  }

  return ret;
}
//========= END YUBIKEY STUFF ========= 



//========= BEGIN LUKS STUFF ========= 
//Based on cryptsetup.c, returns 1 if it contains a luks device
int is_luks(char* file) {
  int ret = 0;
  struct crypt_device *cd = NULL;

  if (crypt_init(&cd, file)) goto out;
  if (crypt_load(cd, CRYPT_LUKS1, NULL)) goto out;
  
  ret = 1;
  
out:
  crypt_free(cd);
  return ret;
}

//Returns 1 if name is an active device
int is_active(char* name) {
  crypt_status_info ci;
  ci = crypt_status(NULL, name);
  
  if (ci == CRYPT_ACTIVE || ci == CRYPT_BUSY) {
    return 1;
  } else {
    return 0;
  }
}

//Set the new key in LUKS_SLOT
int set_key(char* file, unsigned char* old_key, unsigned char* key)
{
  int ret = 0;
  struct crypt_device *cd = NULL;
  char* vk = NULL; size_t vk_size;

  //initialize and load
  if ((crypt_init(&cd, file))) goto out;
  if ((crypt_load(cd, CRYPT_LUKS1, NULL))) goto out;
  
  //If we have an old key, try to get the volume key so we can replace it safely
  if (old_key != NULL) {
    vk_size = crypt_get_volume_key_size(cd);
    vk = malloc(vk_size);
    if (!vk) {
      fprintf(stderr,"Error: could not alloc vk\n");
      goto out;
    }
    
    if (crypt_volume_key_get(cd, LUKS_KEY_SLOT, vk, &vk_size, (char*)old_key, HASH_LENGTH) < 0) {
      fprintf(stderr,"Error: could not read vk\n");
      free(vk);
      vk = NULL;
    }
  }
  
  crypt_set_iteration_time(cd, LUKS_ITERATION_MS);
  
  //Destroy current key (ignore errors)
  crypt_keyslot_destroy(cd, LUKS_KEY_SLOT);
  
  //If we have at this point the volume key, we can use it for the new key, otherwise we ask for passphrase
  if (vk == NULL) {
    //Ask for the challenge
    fprintf(stderr, "set_key: old challenge response didn't work, try yourself:\n");
    if (crypt_keyslot_add_by_passphrase(cd, LUKS_KEY_SLOT, NULL, 0, (char*)key, HASH_LENGTH) < 0) {
      fprintf(stderr, "Error: crypt_keyslot_add_by_passphrase failed\n");
      goto out;
    }
  } else {
    //Use directly the new challenge
    if (crypt_keyslot_add_by_volume_key(cd, LUKS_KEY_SLOT, vk, vk_size, (char*)key, HASH_LENGTH) < 0) {
      fprintf(stderr, "Error: crypt_keyslot_add_by_volume_key failed\n");
      goto out;
    }
  }
  
  //If we get here, evything is fine
  ret = 1;
  
out:
  //Free
  if (vk) free(vk);
  crypt_free(cd);
  return ret;
}

//Open the device with the key
static int luksOpen(char* file, char* activated_name, unsigned char* key) {
  int ret = 0;
  struct crypt_device *cd = NULL;
  
  //Load
  if ((crypt_init(&cd, file))) goto out;
  if ((crypt_load(cd, CRYPT_LUKS1, NULL))) goto out;

  //If we have a challenge, use it (otherwise: ask for passphrase)
  if (key != NULL) {
    if (crypt_activate_by_passphrase(cd, activated_name, LUKS_KEY_SLOT, (char*) key, HASH_LENGTH, LUKS_FLAGS) < 0) {
      fprintf(stderr, "Error: crypt_activate_by_passphrase (challenge) failed\n");
      goto out;
    }
  } else {
    //3 times max
    crypt_set_password_retry(cd, 3);
    if (crypt_activate_by_passphrase(cd, activated_name, CRYPT_ANY_SLOT, NULL, 0, LUKS_FLAGS) < 0) {
      fprintf(stderr, "Error: crypt_activate_by_passphrase failed\n");
      goto out;
    }
  }
  ret = 1;
  
out:
  crypt_free(cd);
  return ret;
}


//========= END LUKS STUFF ========= 



//========= BEGIN LUKS RAW STUFF =========

/* The basic idea here is to use the last slot to store the challenge.
 * Since there is no direct way of doing this in the libcryptsetup API, we
 * directly use a small extension of the LUKS on-disk-format.
 * (see http://code.google.com/p/cryptsetup/wiki/Specification)
 * 
 * Instead of the normal key slot format, we use:
 * 
 * active: CHAL (magic)
 * iteration: 0x0000 (ignored)
 * salt: YKL<version: 1 byte><challenge:20 bytes><11 ignored bytes>
 * key-material-offset: ignored
 * striped: ignored
 * 
 * Version is 1, at present.
 * 
 * CHAL in the active fields makes cryptsetup ignore this slot.
 * 
 */

//Set the challenge
int set_challenge(char* file, unsigned char* challenge) {  
  int ret = 0;
  
  FILE *device;
  device = fopen(file, "r+");
  fseek(device, LUKS_CHALLENGE_KEY_SLOT_OFFSET, SEEK_SET);
  if (fwrite("CHAL\x00\x00\x00\x00", 1, 8, device) != 8) {
    fprintf(stderr, "Error: unable to write keyslot 8/CHAL\n");
    goto out;
  }
  
  if (fwrite("YKL\x01", 1, 4, device) != 4) {
    fprintf(stderr, "Error: unable to write magic (YKL version 1) into keyslot 8\n");
    goto out;
  }
  
  if (fwrite(challenge, 1, HASH_LENGTH, device) != HASH_LENGTH) {
    fprintf(stderr, "Error: unable to write challenge into keyslot 8\n");
    goto out;
  }
  
  ret = 1;
  
out:  
  fclose(device);
  return ret;
}

//Read the challenge
int get_challenge(char* file, unsigned char* challenge) {
  char buffer[256];
  int ret = 0;
  
  FILE *device;
  device = fopen(file, "r");
  fseek(device, LUKS_CHALLENGE_KEY_SLOT_OFFSET, SEEK_SET);
  if (fread(buffer, 1, 48, device) != 48) {
    fprintf(stderr, "Error: unable to read keyslot 8\n");
    goto out;
  }
  if (memcmp(buffer, "CHAL", 4) != 0) {
    fprintf(stderr, "Error: magic!=CHAL in keyslot 8\n");
    goto out;
  }
  if (memcmp(buffer+8, "YKL\x01", 4) != 0) {
    fprintf(stderr, "Error: magic!=YKL version 1 in keyslot 8\n");
    goto out;
  }
  memcpy(challenge, buffer+12, HASH_LENGTH);
  ret = 1;
  
out:
  fclose(device);
  return ret;
}
//========= END LUKS RAW STUFF ========= 

//This is not supposed to be strong crypto, it's only to ensure it's not possible to guess easily the next challenge.
int make_new_challenge(unsigned char *src, unsigned char *new_challenge) {
  int i;
  long* pos;
  struct timespec tp;
  char new_buffer[HASH_LENGTH + sizeof(long)];
  
  memcpy(new_buffer, src, HASH_LENGTH);
  
  for (i=0; i < HASH_LENGTH; i += 1) {
    pos = (long*)(new_buffer+i);
    clock_gettime(CLOCK_REALTIME, &tp);
    *pos ^= tp.tv_nsec;
  }
  memcpy(new_challenge, new_buffer, HASH_LENGTH);
  
  return 1;
}

//Create a random challenge
int get_random_challenge(unsigned char* challenge) {
  int ret = 0;
  FILE *random;
  
  random = fopen("/dev/random","r");
  
  if (fread(challenge, 1, HASH_LENGTH, random) == HASH_LENGTH) {
    ret = 1;
  }
  
  fclose(random);
  return ret;
}


int main(int argc, char **argv) {
  int luks_opened = 0;
  int write_new_challenge = 0;
  
  unsigned char challenge[HASH_LENGTH];
  unsigned char response[HASH_LENGTH];
  unsigned char new_challenge[HASH_LENGTH];
  unsigned char new_response[HASH_LENGTH];
  
  if (argc != 3) {
    fprintf(stderr,"Usage: %s [device] [name]\n",argv[0]);
    return 1;
  }
  
  if (!is_luks(argv[1])) {
    fprintf(stderr,"Error: unable to open LUKS device (not root/invalid file?)\n");
    return 1;
  }
  
  if (is_active(argv[2])) {
    fprintf(stderr,"Error: device %s is already active\n", argv[2]);
    return 1;
  }
  
  fprintf(stderr, "Reading challenge...");
  if (!get_challenge(argv[1],challenge)) {
    fprintf(stderr,"Error: unable to read challenge, using /dev/random!\n");
    if (!get_random_challenge(challenge)) {
      fprintf(stderr,"Error: unable to use /dev/random!\n");
      return 1;
    }
  }
  fprintf(stderr, "done!\n");
  
  fprintf(stderr, "Challenging the Yubikey...");
  if (yk_query(challenge, response, new_challenge, new_response)) {
    //Ok we are successful, so we need to write new challenge
    write_new_challenge = 1;
    fprintf(stderr, "done!\n");
    
    fprintf(stderr, "Opening LUKS device...");
    if (luksOpen(argv[1], argv[2], response)) {
      fprintf(stderr, "done!\n");
      luks_opened = 1;
    } else {
      fprintf(stderr, "Error: could not open device with challenge response, try yourself: \n");
    }
  }
  
  
  if (!luks_opened) {
    if (!luksOpen(argv[1], argv[2], NULL)) {
      fprintf(stderr, "Error: could not unlock device!\n");
      return 1;
    }
  }
  
  if (write_new_challenge) {
    fprintf(stderr, "Writing new challenge...");
    if (!set_challenge(argv[1], new_challenge)) {
      fprintf(stderr, "Error: unable to write new challenge, everything may be broken now :-( \n");
      return 1;
    }
    if (!set_key(argv[1], response, new_response)) {
      fprintf(stderr, "Error: unable to write new key, everything may be broken now :-( \n");
      return 1;
    }
    fprintf(stderr, "done!\n");
    
  }
  return 0;
}
