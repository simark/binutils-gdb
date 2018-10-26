/* Serial interface for local (hardwired) serial ports on Un*x like systems

   Copyright (C) 1992-2018 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "defs.h"
#include "serial.h"
#include "ser-base.h"
#include "ser-unix.h"

#include <fcntl.h>
#include <sys/types.h>
#include "terminal.h"
#include <sys/socket.h>
#include "gdb_sys_time.h"

#include "gdb_select.h"
#include "gdbcmd.h"
#include "filestuff.h"
#include <termios.h>

/* The hardwire ops.  */

struct serial_hardwire_ops : public serial_ops
{
  serial_hardwire_ops ()
  : serial_ops ("hardwire")
  {}

  virtual int open (struct serial *, const char *name) override;
  virtual void close (struct serial *) override;
  /* Discard pending output */
  virtual int flush_output (struct serial *) override;
  /* Discard pending input */
  virtual int flush_input (struct serial *) override;
  virtual int send_break (struct serial *) override;
  virtual void go_raw (struct serial *) override;
  virtual serial_ttystate get_tty_state (struct serial *) override;
  virtual serial_ttystate copy_tty_state (struct serial *, serial_ttystate) override;
  virtual int set_tty_state (struct serial *, serial_ttystate) override;
  virtual void print_tty_state (struct serial *, serial_ttystate,
				struct ui_file *) override;
  virtual int setbaudrate (struct serial *, int rate) override;
  virtual int setstopbits (struct serial *, int num) override;
  /* Set the value PARITY as parity setting for serial object.
     Return 0 in the case of success.  */
  virtual int setparity (struct serial *, int parity) override;
  /* Wait for output to drain.  */
  virtual int drain_output (struct serial *) override;
  /* Perform a low-level read operation, reading (at most) COUNT
     bytes into SCB->BUF.  Return zero at end of file.  */
  virtual int read_prim (struct serial *scb, size_t count) override;
  /* Perform a low-level write operation, writing (at most) COUNT
     bytes from BUF.  */
  virtual int write_prim (struct serial *scb, const void *buf, size_t count) override;
};

struct hardwire_ttystate
  {
    struct termios termios;
  };

#ifdef CRTSCTS
/* Boolean to explicitly enable or disable h/w flow control.  */
static int serial_hwflow;
static void
show_serial_hwflow (struct ui_file *file, int from_tty,
		    struct cmd_list_element *c, const char *value)
{
  fprintf_filtered (file, _("Hardware flow control is %s.\n"), value);
}
#endif


/* Open up a real live device for serial I/O.  */

int
serial_hardwire_ops::open (struct serial *scb, const char *name)
{
  scb->fd = gdb_open_cloexec (name, O_RDWR, 0);
  if (scb->fd < 0)
    return -1;

  return 0;
}

static int
get_tty_state (struct serial *scb, struct hardwire_ttystate *state)
{
  if (tcgetattr (scb->fd, &state->termios) < 0)
    return -1;

  return 0;
}

static int
set_tty_state (struct serial *scb, struct hardwire_ttystate *state)
{
  if (tcsetattr (scb->fd, TCSANOW, &state->termios) < 0)
    return -1;

  return 0;
}

serial_ttystate
serial_hardwire_ops::get_tty_state (struct serial *scb)
{
  struct hardwire_ttystate *state = XNEW (struct hardwire_ttystate);

  if (::get_tty_state (scb, state))
    {
      xfree (state);
      return NULL;
    }

  return (serial_ttystate) state;
}

serial_ttystate
serial_hardwire_ops::copy_tty_state (struct serial *scb, serial_ttystate ttystate)
{
  struct hardwire_ttystate *state = XNEW (struct hardwire_ttystate);

  *state = *(struct hardwire_ttystate *) ttystate;

  return (serial_ttystate) state;
}

int
serial_hardwire_ops::set_tty_state (struct serial *scb, serial_ttystate ttystate)
{
  struct hardwire_ttystate *state;

  state = (struct hardwire_ttystate *) ttystate;

  return ::set_tty_state (scb, state);
}

void
serial_hardwire_ops::print_tty_state (struct serial *scb,
				      serial_ttystate ttystate,
				      struct ui_file *stream)
{
  struct hardwire_ttystate *state = (struct hardwire_ttystate *) ttystate;
  int i;

  fprintf_filtered (stream, "c_iflag = 0x%x, c_oflag = 0x%x,\n",
		    (int) state->termios.c_iflag,
		    (int) state->termios.c_oflag);
  fprintf_filtered (stream, "c_cflag = 0x%x, c_lflag = 0x%x\n",
		    (int) state->termios.c_cflag,
		    (int) state->termios.c_lflag);
#if 0
  /* This not in POSIX, and is not really documented by those systems
     which have it (at least not Sun).  */
  fprintf_filtered (stream, "c_line = 0x%x.\n", state->termios.c_line);
#endif
  fprintf_filtered (stream, "c_cc: ");
  for (i = 0; i < NCCS; i += 1)
    fprintf_filtered (stream, "0x%x ", state->termios.c_cc[i]);
  fprintf_filtered (stream, "\n");
}

/* Wait for the output to drain away, as opposed to flushing
   (discarding) it.  */

int
serial_hardwire_ops::drain_output (struct serial *scb)
{
  return tcdrain (scb->fd);
}

int
serial_hardwire_ops::flush_output (struct serial *scb)
{
  return tcflush (scb->fd, TCOFLUSH);
}

int
serial_hardwire_ops::flush_input (struct serial *scb)
{
  serial_ops::flush_input (scb);

  return tcflush (scb->fd, TCIFLUSH);
}

int
serial_hardwire_ops::send_break (struct serial *scb)
{
  return tcsendbreak (scb->fd, 0);
}

void
serial_hardwire_ops::go_raw (struct serial *scb)
{
  struct hardwire_ttystate state;

  if (::get_tty_state (scb, &state))
    fprintf_unfiltered (gdb_stderr, "get_tty_state failed: %s\n",
			safe_strerror (errno));

  state.termios.c_iflag = 0;
  state.termios.c_oflag = 0;
  state.termios.c_lflag = 0;
  state.termios.c_cflag &= ~CSIZE;
  state.termios.c_cflag |= CLOCAL | CS8;
#ifdef CRTSCTS
  /* h/w flow control.  */
  if (serial_hwflow)
    state.termios.c_cflag |= CRTSCTS;
  else
    state.termios.c_cflag &= ~CRTSCTS;
#ifdef CRTS_IFLOW
  if (serial_hwflow)
    state.termios.c_cflag |= CRTS_IFLOW;
  else
    state.termios.c_cflag &= ~CRTS_IFLOW;
#endif
#endif
  state.termios.c_cc[VMIN] = 0;
  state.termios.c_cc[VTIME] = 0;

  if (::set_tty_state (scb, &state))
    fprintf_unfiltered (gdb_stderr, "set_tty_state failed: %s\n",
			safe_strerror (errno));
}

#ifndef B19200
#define B19200 EXTA
#endif

#ifndef B38400
#define B38400 EXTB
#endif

/* Translate baud rates from integers to damn B_codes.  Unix should
   have outgrown this crap years ago, but even POSIX wouldn't buck it.  */

static struct
{
  int rate;
  int code;
}
baudtab[] =
{
  {
    50, B50
  }
  ,
  {
    75, B75
  }
  ,
  {
    110, B110
  }
  ,
  {
    134, B134
  }
  ,
  {
    150, B150
  }
  ,
  {
    200, B200
  }
  ,
  {
    300, B300
  }
  ,
  {
    600, B600
  }
  ,
  {
    1200, B1200
  }
  ,
  {
    1800, B1800
  }
  ,
  {
    2400, B2400
  }
  ,
  {
    4800, B4800
  }
  ,
  {
    9600, B9600
  }
  ,
  {
    19200, B19200
  }
  ,
  {
    38400, B38400
  }
  ,
#ifdef B57600
  {
    57600, B57600
  }
  ,
#endif
#ifdef B115200
  {
    115200, B115200
  }
  ,
#endif
#ifdef B230400
  {
    230400, B230400
  }
  ,
#endif
#ifdef B460800
  {
    460800, B460800
  }
  ,
#endif
  {
    -1, -1
  }
  ,
};

static int
rate_to_code (int rate)
{
  int i;

  for (i = 0; baudtab[i].rate != -1; i++)
    {
      /* test for perfect macth.  */
      if (rate == baudtab[i].rate)
        return baudtab[i].code;
      else
        {
	  /* check if it is in between valid values.  */
          if (rate < baudtab[i].rate)
	    {
	      if (i)
	        {
	          warning (_("Invalid baud rate %d.  "
			     "Closest values are %d and %d."),
			   rate, baudtab[i - 1].rate, baudtab[i].rate);
		}
	      else
	        {
	          warning (_("Invalid baud rate %d.  Minimum value is %d."),
			   rate, baudtab[0].rate);
		}
	      return -1;
	    }
        }
    }
 
  /* The requested speed was too large.  */
  warning (_("Invalid baud rate %d.  Maximum value is %d."),
            rate, baudtab[i - 1].rate);
  return -1;
}

int
serial_hardwire_ops::setbaudrate (struct serial *scb, int rate)
{
  struct hardwire_ttystate state;
  int baud_code = rate_to_code (rate);
  
  if (baud_code < 0)
    {
      /* The baud rate was not valid.
         A warning has already been issued.  */
      errno = EINVAL;
      return -1;
    }

  if (::get_tty_state (scb, &state))
    return -1;

  cfsetospeed (&state.termios, baud_code);
  cfsetispeed (&state.termios, baud_code);

  return ::set_tty_state (scb, &state);
}

int
serial_hardwire_ops::setstopbits (struct serial *scb, int num)
{
  struct hardwire_ttystate state;
  int newbit;

  if (::get_tty_state (scb, &state))
    return -1;

  switch (num)
    {
    case SERIAL_1_STOPBITS:
      newbit = 0;
      break;
    case SERIAL_1_AND_A_HALF_STOPBITS:
    case SERIAL_2_STOPBITS:
      newbit = 1;
      break;
    default:
      return 1;
    }

  if (!newbit)
    state.termios.c_cflag &= ~CSTOPB;
  else
    state.termios.c_cflag |= CSTOPB;	/* two bits */

  return ::set_tty_state (scb, &state);
}

/* Implement the "setparity" serial_ops callback.  */

int
serial_hardwire_ops::setparity (struct serial *scb, int parity)
{
  struct hardwire_ttystate state;
  int newparity = 0;

  if (::get_tty_state (scb, &state))
    return -1;

  switch (parity)
    {
    case GDBPARITY_NONE:
      newparity = 0;
      break;
    case GDBPARITY_ODD:
      newparity = PARENB | PARODD;
      break;
    case GDBPARITY_EVEN:
      newparity = PARENB;
      break;
    default:
      internal_warning (__FILE__, __LINE__,
			"Incorrect parity value: %d", parity);
      return -1;
    }

  state.termios.c_cflag &= ~(PARENB | PARODD);
  state.termios.c_cflag |= newparity;

  return ::set_tty_state (scb, &state);
}


void
serial_hardwire_ops::close (struct serial *scb)
{
  if (scb->fd < 0)
    return;

  ::close (scb->fd);
  scb->fd = -1;
}

static struct serial_hardwire_ops serial_hardwire_ops;

void
_initialize_ser_hardwire (void)
{
  serial_add_interface (&serial_hardwire_ops);

#ifdef CRTSCTS
  add_setshow_boolean_cmd ("remoteflow", no_class,
			   &serial_hwflow, _("\
Set use of hardware flow control for remote serial I/O."), _("\
Show use of hardware flow control for remote serial I/O."), _("\
Enable or disable hardware flow control (RTS/CTS) on the serial port\n\
when debugging using remote targets."),
			   NULL,
			   show_serial_hwflow,
			   &setlist, &showlist);
#endif
}

int
ser_unix_read_prim (struct serial *scb, size_t count)
{
  return read (scb->fd, scb->buf, count);
}

int
serial_hardwire_ops::read_prim (struct serial *scb, size_t count)
{
  return ser_unix_read_prim (scb, count);
}

int
ser_unix_write_prim (struct serial *scb, const void *buf, size_t len)
{
  return write (scb->fd, buf, len);
}

int
serial_hardwire_ops::write_prim (struct serial *scb, const void *buf, size_t len)
{
  return ser_unix_write_prim (scb, buf, len);
}
