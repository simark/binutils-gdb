/* Serial interface for local domain connections on Un*x like systems.

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

#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include "netstuff.h"

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX sizeof(((struct sockaddr_un *) NULL)->sun_path)
#endif

struct serial_uds_ops : public serial_ops
{
  serial_uds_ops ()
  : serial_ops ("local")
  {}

  virtual int open (struct serial *, const char *name) override;
  virtual void close (struct serial *) override;

  /* Perform a low-level read operation, reading (at most) COUNT
     bytes into SCB->BUF.  Return zero at end of file.  */
  virtual int read_prim (struct serial *scb, size_t count) override;
  /* Perform a low-level write operation, writing (at most) COUNT
     bytes from BUF.  */
  virtual int write_prim (struct serial *scb, const void *buf, size_t count) override;
};


/* Open an AF_UNIX socket.  */

int
serial_uds_ops::open (struct serial *scb, const char *name)
{
  struct addrinfo hint;

  memset (&hint, 0, sizeof (hint));
  /* Assume no prefix will be passed, therefore we should use
     AF_UNSPEC.  */
  hint.ai_family = AF_UNSPEC;
  hint.ai_socktype = SOCK_STREAM;

  parsed_connection_spec parsed = parse_connection_spec (name, &hint);

  const char *socket_name = parsed.port_str.empty() ? name : parsed.port_str.c_str ();

  struct sockaddr_un addr;

  if (strlen (socket_name) > UNIX_PATH_MAX - 1)
    {
      warning
        (_("The socket name is too long.  It may be no longer than %s bytes."),
         pulongest (UNIX_PATH_MAX - 1L));
      return -1;
    }

  memset (&addr, 0, sizeof addr);
  addr.sun_family = AF_UNIX;
  strncpy (addr.sun_path, socket_name, UNIX_PATH_MAX - 1);

  int sock = socket (AF_UNIX, SOCK_STREAM, 0);

  if (connect (sock, (struct sockaddr *) &addr,
	       sizeof (struct sockaddr_un)) < 0)
    {
      ::close (sock);
      scb->fd = -1;
      return -1;
    }

  scb->fd = sock;

  return 0;
}

void
serial_uds_ops::close (struct serial *scb)
{
  if (scb->fd == -1)
    return;

  ::close (scb->fd);
  scb->fd = -1;
}

int
serial_uds_ops::read_prim (struct serial *scb, size_t count)
{
  return recv (scb->fd, scb->buf, count, 0);
}

int
serial_uds_ops::write_prim (struct serial *scb, const void *buf, size_t count)
{
  return send (scb->fd, buf, count, 0);
}

static struct serial_uds_ops serial_uds_ops;

void
_initialize_ser_socket (void)
{
  serial_add_interface (&serial_uds_ops);
}
