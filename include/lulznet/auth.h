/*
 * "auth.h" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
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

/* This is where lulznet saves users credentials */
#define CREDENTIAL_FILE "/etc/lulznet/credential"

#define AUTHENTICATION_FAILED		'\x00'
#define AUTHENTICATION_SUCCESSFULL 	'\x01'

#define MAX_USERNAME_LEN	16
#define MAX_PASSWORD_LEN	32
#define PW_HASH_STRING_LEN	32

/* Global var where we save password so you don't have
   to retype it everytime */
extern char *saved_password;

void auth_service(SSL *ssl);

/* Check if hash match username (local for now */
int do_authentication (char *username, u_char * hash);

/* Ask for password (disable echo */
char *password_prompt ();

/* Check if there's a saved password, else ask for a password */
char *get_password ();

/* return string's md5 */
u_char *calculate_md5 (char *string);

/* Function to return a line of the credential file */
int get_user_credential (FILE * fp, char *username, char *hash);

/* Parse each line of credential file to get username and hash */
char *get_hash (char *request_user);

/* return a string with ssl'peer certificate fingerprint */
char *get_fingerprint_from_ctx (SSL * ssl);
