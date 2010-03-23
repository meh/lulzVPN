#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

int
main (int argc, char *argv[])
{
  EVP_MD_CTX mdctx;
  const EVP_MD *md;
  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_len, i;
  char digest[33];

  if (argc != 2)
    {
      printf ("Usage: %s password\n", argv[0]);
      return 1;
    }

  OpenSSL_add_all_digests ();

  md = EVP_get_digestbyname ("MD5");

  EVP_MD_CTX_init (&mdctx);
  EVP_DigestInit_ex (&mdctx, md, NULL);
  EVP_DigestUpdate (&mdctx, argv[1], strlen (argv[1]));
  EVP_DigestFinal_ex (&mdctx, md_value, &md_len);
  EVP_MD_CTX_cleanup (&mdctx);

  for (i = 0; i < md_len; i++)
      sprintf (digest + (i * 2), "%02x", md_value[i]);
  printf ("%s\n", digest);

  return 0;
}
