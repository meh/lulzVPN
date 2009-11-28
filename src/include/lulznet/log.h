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

#include <pthread.h>

#ifndef _LNET_LOG_H
#define _LNET_LOG_H

namespace Log
{

#define INFO		1
#define DEBUG_1		2
#define DEBUG_2		3
#define DEBUG_3		4
#define ERROR		5
#define FATAL		6
#define MAXLOGSIZE	512

extern pthread_mutex_t mutex;

/* Call appropriate log function */
void DoLog (const char *fmt, va_list args, int level);

/* Print to stderr various messages */
void Info (const char *msg, ...);
void Debug1 (const char *msg, ...);
void Debug2 (const char *msg, ...);
void Debug3 (const char *msg, ...);
void Error (const char *msg, ...);
void Fatal (const char *msg, ...);
void ShellMsg (const char *msg, ...);

/* Dump in ascii and hex data_buffer */
void dump (unsigned char *data_buffer, int length);
}

#endif
