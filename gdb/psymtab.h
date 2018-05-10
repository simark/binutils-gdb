/* Public partial symbol table definitions.

   Copyright (C) 2009-2018 Free Software Foundation, Inc.

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

#ifndef PSYMTAB_H
#define PSYMTAB_H

#include "symfile.h"

/* A bcache for partial symbols.  */

struct compunit_symtab;
struct partial_symtab;
struct psymbol_bcache;

extern struct psymbol_bcache *psymbol_bcache_init (void);
extern void psymbol_bcache_free (struct psymbol_bcache *);
extern struct bcache *psymbol_bcache_get_bcache (struct psymbol_bcache *);

extern const struct quick_symbol_functions psym_functions;

extern const struct quick_symbol_functions dwarf2_gdb_index_functions;
extern const struct quick_symbol_functions dwarf2_debug_names_functions;

/* Ensure that the partial symbols for OBJFILE have been loaded.  If
   VERBOSE is non-zero, then this will print a message when symbols
   are loaded.  This function always returns its argument, as a
   convenience.  */

extern struct objfile *require_partial_symbols (struct objfile *objfile,
						int verbose);

/* Record that, for the given objfile, PST has expanded to SYMTAB.
   SYMTAB may be nullptr, indicating that an attempt to expand PST was
   made, but yielded no results (perhaps this was an included
   psymtab).  By default, this association is always made, but if
   ALWAYS_SET is false, then an association is only made if one has
   not been made previously.  */

extern void associate_psymtab_with_symtab (struct objfile *objfile,
					   partial_symtab *pst,
					   compunit_symtab *symtab,
					   bool always_set = true);

/* Return true if PST was ever read in for the given objfile, false
   otherwise.  This only records whether an attempt was made -- not
   whether it yielded a full symtab.  */

extern bool psymtab_read_in_p (struct objfile *objfile, partial_symtab *pst);

/* Return the full symtab corresponding to PST.  Returns NULL if the
   partial symtab was never read, or if the attempt to read it yielded
   no results.  */

extern compunit_symtab *get_psymtab_compunit (struct objfile *objfile,
					      partial_symtab *pst);

#endif /* PSYMTAB_H */
