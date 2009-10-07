/*
 * "auth.c" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
 *
 * lulzNet is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * lulzNet is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
*/

#include "headers/lulznet.h"

int
do_authentication (char *username, u_char * hash)
{

  char str_hash[PW_HASH_STRING_LEN + 1];
  char *local_hash;

  int response;
  int i;

  if ((local_hash = get_hash (username)) != NULL)
    {
      for (i = 0; i < MD5_DIGEST_LENGTH; i++)
	sprintf (str_hash + (i * 2), "%02x", hash[i]);

      if (!strcmp (str_hash, local_hash))
	response = TRUE;
      else
	{
	  error ("Wrong password");
	  response = FALSE;
	}
    }
  else
    {
      error ("Cannot find user");
      response = FALSE;
    }

  free (local_hash);
  return response;
}

char *
password_prompt ()
{

  char *password;
  struct termio tty, oldtty;

  password = xmalloc ((MAX_PASSWORD_LEN + 1) * sizeof (char));

  ioctl (0, TCGETA, &oldtty);

  tty = oldtty;
  tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ECHOK | ECHONL);
  tty.c_cc[VMIN] = 1;
  tty.c_cc[VTIME] = 0;

  ioctl (0, TCSETA, &tty);

  printf ("\nPassword: ");
  scanf ("%32s", password);

  ioctl (0, TCSETA, &oldtty);

  return password;
}

char *
get_password ()
{
  /* Global pw var */
  if (saved_password == NULL)
    saved_password = password_prompt ();

  return saved_password;
}

u_char *
calculate_md5 (char *string)
{

  EVP_MD_CTX mdctx;
  const EVP_MD *md;
  u_int md_len;

  u_char *hex_hash = xmalloc (MD5_DIGEST_LENGTH * sizeof (u_char));

  md = EVP_get_digestbyname ("MD5");
  EVP_MD_CTX_init (&mdctx);
  EVP_DigestInit_ex (&mdctx, md, NULL);
  EVP_DigestUpdate (&mdctx, string, strlen (string));
  EVP_DigestFinal_ex (&mdctx, hex_hash, &md_len);
  EVP_MD_CTX_cleanup (&mdctx);

  return hex_hash;
}

int
get_user_credential (FILE * fp, char *username, char *hash)
{
  int len;

  fscanf (fp, "%16s %32s", username, hash);

  if (!(len = strlen (username)))
    return 0;

  return 1;
}

char *
get_hash (char *request_user)
{

  FILE *cred;
  char user[MAX_USERNAME_LEN + 1];
  char *hash;

  hash = xmalloc ((PW_HASH_STRING_LEN + 1) * sizeof (char));
  cred = fopen (CREDENTIAL_FILE, "r");

  if (cred == NULL)
    {
      error ("Cannot open credential file %s", CREDENTIAL_FILE);
      return NULL;
    }

  while (get_user_credential (cred, user, hash))
    {
      if (!strcmp (user, request_user))
	return hash;
    }

  return NULL;
}

char *
get_fingerprint_from_ctx (SSL * ssl)
{

  u_char digest[SHA_DIGEST_LENGTH];
  char hex[] = "0123456789ABCDEF";
  char *fp = malloc ((EVP_MAX_MD_SIZE * 3) * sizeof (char));
  u_int len;
  u_int i;

  X509 *cert;

  cert = SSL_get_peer_certificate (ssl);
  X509_digest (cert, EVP_md5 (), digest, &len);

  for (i = 0; i < len; i++)
    {
      fp[i * 3 + 0] = hex[(digest[i] >> 4) & 0xF];
      fp[i * 3 + 1] = hex[(digest[i] >> 0) & 0xF];
      fp[i * 3 + 2] = i == len - 1 ? '\0' : ':';
    }

  return fp;
}
