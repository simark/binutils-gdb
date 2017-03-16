#ifndef GDB_MMAP_H
#define GDB_MMAP_H

#include "filestuff.h"
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

/* Call munmap on scope exit.  */

struct gdb_munmapper
{
  gdb_munmapper ()
  {}

  gdb_munmapper (void *addr, size_t size)
  : m_addr (addr), m_size (size)
  {}

  gdb_munmapper (gdb_munmapper &&other)
  {
    do_move (other);
  }

  gdb_munmapper &operator= (gdb_munmapper &&other)
  {
    maybe_unmap ();
    do_move (other);

    return *this;
  }

  ~gdb_munmapper ()
  {
    maybe_unmap ();
  }

  DISABLE_COPY_AND_ASSIGN (gdb_munmapper);

  void reset (void *addr, size_t size)
  {
    maybe_unmap ();
    m_addr = addr;
    m_size = size;
  }

  void *addr ()
  { return m_addr; }

  size_t size ()
  { return m_size; }

private:

  void maybe_unmap ()
  {
    if (m_addr != NULL)
      munmap (m_addr, m_size);
  }

  void do_move (gdb_munmapper &other)
  {
    this->m_addr = other.m_addr;
    other.m_addr = NULL;

    this->m_size = other.m_size;
    other.m_size = 0;
  }

  void *m_addr = NULL;
  size_t m_size = 0;
};

/* mmap a file (read-only) in GDB's address space.  */

class mmap_file
{
public:
  mmap_file (const char *file)
  {
    int fd = open (file, 0, O_RDONLY);
    if (fd < 1)
      error ("open");

    m_fd.reset (fd);

    off_t size = lseek (fd, 0, SEEK_END);
    if (size < 0)
      error ("lseek");

    // Necessary?
    lseek (fd, 0, SEEK_SET);

    void *addr = mmap (NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (addr == MAP_FAILED)
      error ("mmap");

    m_mapping.reset (addr, size);
  }

  void *addr ()
  { return m_mapping.addr (); }

  size_t size ()
  { return m_mapping.size (); }

private:

  gdb_fd_closer m_fd;
  gdb_munmapper m_mapping;
};

#endif
