/*
 * "log.h" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
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

#define INFO		1
#define DEBUG_1		2
#define DEBUG_2		3
#define DEBUG_3		4
#define ERROR		5
#define FATAL		6
#define SHELL_MSG	7

#define MAXLOGSIZE	512

int debug_level;
pthread_mutex_t log_mutex;

/* Call appropriate log function */
void do_log (char *fmt, va_list args, int level);

/* Print to stderr various messages */
void info (char *msg, ...);
void debug1 (char *msg, ...);
void debug2 (char *msg, ...);
void debug3 (char *msg, ...);
void error (char *msg, ...);
void fatal (char *msg, ...);
void shell_msg (char *msg, ...);

/* Dump in ascii and hex data_buffer */
void dump (char *data_buffer, int length);
