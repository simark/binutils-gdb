#ifndef INDEX_CACHE_H
#define INDEX_CACHE_H

#include "dwarf2read.h"

class index_cache
{
public:
  void set_directory (const char *dir);

  bool enabled () const
  {
    return m_enabled;
  }

  void enable ();
  void disable ();

  /* Store an index for the specified object file in the cache.  */
  void store (struct dwarf2_per_objfile *dwarf2_per_objfile);

  /* Try to read an index from this cache for the specified object file.  */
  bool read (struct dwarf2_per_objfile *dwarf2_per_objfile,
	     const char *filename,
	     int deprecated_ok,
	     struct mapped_index *map,
	     const gdb_byte **cu_list,
	     offset_type *cu_list_elements,
	     const gdb_byte **types_list,
	     offset_type *types_list_elements);

  unsigned int n_hits ()
  {
    return m_n_hits;
  }

  unsigned int n_misses ()
  {
    return m_n_misses;
  }

private:

  /* Get the location of the index cache file for OBJ.  */
  std::string make_cache_filename (objfile *obj);

  /* The base directory of the index cache.  A value of NULL means that the
     cache is closed/not enabled. */
  const char *m_dir = NULL;

  bool m_enabled = false;

  /* Number of cache hits and misses during this GDB session.  */
  unsigned int m_n_hits = 0;
  unsigned int m_n_misses = 0;
};

extern index_cache global_index_cache;

#endif
