/*
 * "auth.cpp" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
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

#include <lulznet/lulznet.h>

#include <lulznet/auth.h>
#include <lulznet/config.h>
#include <lulznet/log.h>

bool
Auth::DoAuthentication (const std::string& Username, uChar * Hash)
{
  std::string StrHash;
  std::string LocalHash;
  char tmp[3];
  int Response;
  int i;

  Response = false;

  LocalHash = GetHash(Username);
  if (!LocalHash.empty()) {
    for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
      sprintf(tmp, "%02x", Hash[i]);
      StrHash.append(tmp);
    }
    if (!StrHash.compare(LocalHash))
      Response = true;
    else
      Log::Error("Wrong Password");
  }
  else
    Log::Error("Cannot find user");

  return Response;
}

void
Auth::PasswordPrompt ()
{

  std::string Password;
  struct termio tty, oldtty;

  ioctl(0, TCGETA, &oldtty);

  tty = oldtty;
  tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ECHOK | ECHONL);
  tty.c_cc[VMIN] = 1;
  tty.c_cc[VTIME] = 0;

  ioctl(0, TCSETA, &tty);

  std::cout << "Password: ";
  std::cin >> Password;
  std::cout << std::endl;

  ioctl(0, TCSETA, &oldtty);

  Options.Password(Password);
}

std::string
Auth::GetHash (const std::string& RequestedUser)
{
  std::string Hash;
  std::vector<UserCredentialT>::const_iterator ucIt, ucEnd;

  ucEnd = Options.UserCredentials().end();
  for (ucIt = Options.UserCredentials().begin(); ucIt < ucEnd; ++ucIt)
    if (!(*ucIt).Name.compare(RequestedUser))
      return (*ucIt).Hash;

  Hash.clear();
  return Hash;
}

uChar *
Auth::Crypt::CalculateMd5 (const std::string& string)
{
  EVP_MD_CTX mdctx;
  const EVP_MD *md;
  uInt md_len;
  uChar *HexHash;

  try {
       HexHash = new uChar[MD5_DIGEST_LENGTH];
  } catch(const std::bad_alloc& x) {
       Log::Fatal("Out of memory");
  }

  md = EVP_get_digestbyname("MD5");
  EVP_MD_CTX_init(&mdctx);
  EVP_DigestInit_ex(&mdctx, md, NULL);
  EVP_DigestUpdate(&mdctx, string.c_str(), string.length());
  EVP_DigestFinal_ex(&mdctx, HexHash, &md_len);
  EVP_MD_CTX_cleanup(&mdctx);

  return HexHash;
}

char *
Auth::Crypt::GetFingerprintFromCtx (SSL *ssl)
{
  uChar digest[SHA_DIGEST_LENGTH];
  char hex[] = "0123456789ABCDEF";
  char *fp;
  uInt len;
  uInt i;
  X509 *cert;

  try {
  fp = new char[EVP_MAX_MD_SIZE * 3];
  } catch (const std::bad_alloc& x) {
       Log::Fatal("Out of memory");
  }
  cert = SSL_get_peer_certificate(ssl);
  X509_digest(cert, EVP_md5(), digest, &len);

  for (i = 0; i < len; i++) {
    fp[i * 3 + 0] = hex[(digest[i] >> 4) & 0xF];
    fp[i * 3 + 1] = hex[(digest[i] >> 0) & 0xF];
    fp[i * 3 + 2] = i == len - 1 ? '\0' : ':';
  }

  return fp;
}
