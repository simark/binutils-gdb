#ifndef DWARF2_INDEX
#define DWARF2_INDEX

#include "common/array-view.h"
#include "dwarf2read.h"

/* The suffix for an index file.  */
#define INDEX_SUFFIX ".gdb-index"

struct index_provider
{
  virtual ~index_provider () = default;
};

int read_index_from_section (struct objfile *objfile,
			     const char *filename,
			     int deprecated_ok,
			     struct dwarf2_section_info *section,
			     struct mapped_index *map,
			     const gdb_byte **cu_list,
			     offset_type *cu_list_elements,
			     const gdb_byte **types_list,
			     offset_type *types_list_elements);

int read_index_from_buffer (const char *filename,
			    int deprecated_ok,
			    const gdb::array_view<gdb_byte> &buffer,
			    struct mapped_index *map,
			    const gdb_byte **cu_list,
			    offset_type *cu_list_elements,
			    const gdb_byte **types_list,
			    offset_type *types_list_elements);

void write_psymtabs_to_index (struct dwarf2_per_objfile *dwarf2_per_objfile,
			      const char *filename);

#endif
