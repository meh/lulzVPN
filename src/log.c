/*
 * "log.c" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
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
#include <lulznet/log.h>

int debug_level;
pthread_mutex_t log_mutex;

void
info (const char *msg, ...)
{

  va_list args;

  va_start (args, msg);
  do_log (msg, args, INFO);
  va_end (args);
}

void
debug1 (const char *msg, ...)
{
  va_list args;

  if (debug_level < 1)
    {
      return;
    }

  va_start (args, msg);
  do_log (msg, args, DEBUG_1);
  va_end (args);
}

void
debug2 (const char *msg, ...)
{
  va_list args;

  if (debug_level < 2)
    {
      return;
    }

  va_start (args, msg);
  do_log (msg, args, DEBUG_2);
  va_end (args);
}

void
debug3 (const char *msg, ...)
{
  va_list args;

  if (debug_level < 3)
    {
      return;
    }

  va_start (args, msg);
  do_log (msg, args, DEBUG_3);
  va_end (args);
}

void
error (const char *msg, ...)
{
  va_list args;

  va_start (args, msg);
  do_log (msg, args, ERROR);
  va_end (args);
}

void
fatal (const char *msg, ...)
{

  va_list args;

  va_start (args, msg);
  do_log (msg, args, FATAL);
  va_end (args);

  exit_lulznet ();

  exit (1);
}

void
shell_msg (const char *msg, ...)
{
  va_list args;

  va_start (args, msg);
  do_log (msg, args, SHELL_MSG);
  va_end (args);
}

void
do_log (const char *fmt, va_list args, int level)
{
  char msgbuf[MAXLOGSIZE];
  char fmtbuf[MAXLOGSIZE];

  pthread_mutex_lock (&log_mutex);

  switch (level)
    {
    case INFO:
      snprintf (fmtbuf, sizeof (fmtbuf), "\n[inf] %s", fmt);
      break;
    case DEBUG_1:
    case DEBUG_2:
    case DEBUG_3:
      snprintf (fmtbuf, sizeof (fmtbuf), "\n[dbg] %s", fmt);
      break;
    case ERROR:
      snprintf (fmtbuf, sizeof (fmtbuf), "\n[err] %s", fmt);
      break;
    case FATAL:
      snprintf (fmtbuf, sizeof (fmtbuf), "\n[ftl] %s", fmt);
      break;
    case SHELL_MSG:
      snprintf (fmtbuf, sizeof (fmtbuf), "%s\n", fmt);
    }

  vsnprintf (msgbuf, sizeof (msgbuf), fmtbuf, args);
  fprintf (stderr, "%s", msgbuf);
  fflush (stderr);

  /* if specified log file print to it 
     if(opt.log_fp != NULL)
     fprintf(opt.log_fp,"%s",msgbuf");
   */

  pthread_mutex_unlock (&log_mutex);

}

void
dump (char *data_buffer, int length)
{
  char byte;
  int i, j;

  if (debug_level < 4)
    {
      return;
    }

  pthread_mutex_lock (&log_mutex);

  fprintf (stderr, "\n");

  for (i = 0; i < length; i++)
    {
      byte = data_buffer[i];
      fprintf (stderr, "%02x ", data_buffer[i]);
      if (((i % 16) == 15) || (i == length - 1))
	{
	  for (j = 0; j < 15 - (i % 16); j++)
	    fprintf (stderr, "   ");
	  fprintf (stderr, "| ");
	  for (j = (i - (i % 16)); j <= i; j++)
	    {
	      byte = data_buffer[j];
	      if ((byte > 31) && (byte < 127))
		fprintf (stderr, "%c", byte);
	      else
		fprintf (stderr, ".");
	    }
	  fprintf (stderr, "\n");
	}

    }

  pthread_mutex_unlock (&log_mutex);

}
