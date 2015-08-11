#include "defs.h"
#include "probe.h"
#include "vec.h"
#include "elf-bfd.h"
#include "gdbtypes.h"
#include "obstack.h"
#include "objfiles.h"
#include "complaints.h"
#include "value.h"
#include "ax.h"
#include "ax-gdb.h"
#include "language.h"
#include "parser-defs.h"
#include "inferior.h"
#include "gdbcore.h"
#include "valprint.h"

//#include <lttng/tracepoint-types.h>

extern const struct probe_ops lttng_probe_ops;

static int
lttng_is_linespec (const char **linespecp)
{
  return 0;
}

static CORE_ADDR
lttng_get_probe_address (struct probe *probe, struct objfile *objfile)
{
  // TODO: should we add the offset of the objfile?
  return probe->address;
}

static int extract_provider_name (const char *full_name, char **provider, char **name)
{
  /* Pointer to NULL character.  */
  const char *end = full_name + strlen(full_name);
  const char *sep = strchr (full_name, ':');

  if (sep == NULL)
    return 1;

  /* Copy provider.  */
  *provider = xmalloc (sep - full_name + 1);
  strncpy (*provider, full_name, sep - full_name);
  (*provider)[sep - full_name] = '\0';

  /* Skip separator, copy name.  */
  sep++;
  *name = xmalloc (end - sep + 1);
  strcpy (*name, sep);

  return 0;
}


static const char *
read_tracepoint_name (CORE_ADDR tp_struct_addr, struct type *ptr_type,
		      struct gdbarch *arch)
{
  CORE_ADDR name_addr;
  char *full_name;
  int bytes_read, ret;

  name_addr = read_memory_typed_address (tp_struct_addr, ptr_type);

  ret = read_string (name_addr, -1, 1, 256, gdbarch_byte_order (arch),
		     (gdb_byte **) &full_name, &bytes_read);
  if (ret != 0)
    {
      printf ("Couldn't read name\n");
      return NULL;
    }

  return full_name;
}

static void
lttng_get_probes (VEC (probe_p) **probes, struct objfile *objfile)
{
  bfd *abfd = objfile->obfd;
  asection *tp_sect;
  asection *tp_ptrs_sect;
  asection *tp_strings_sect;
  struct gdbarch *arch = get_objfile_arch (objfile);
  struct type * const ptr_type = builtin_type (arch)->builtin_data_ptr;
  bfd_byte *ptr_buf;
  CORE_ADDR ptrs_table_start, ptrs_table_stop, callsites_start, callsites_stop, p;
  struct bound_minimal_symbol ptrs_table_start_sym, ptrs_table_stop_sym,
      callsites_start_sym, callsites_stop_sym;
  bfd_boolean res;
  int ptrs_table_size;
  CORE_ADDR ptrptr;

  printf("Getting probes in %s\n", objfile->original_name);

  /* Do nothing in case this is a .debug file, instead of the objfile
       itself.  */
  if (objfile->separate_debug_objfile_backlink != NULL)
    return;

  callsites_start_sym = lookup_minimal_symbol("__start___lttng_callsites", NULL, objfile);
  if (callsites_start_sym.minsym == NULL)
    {
      printf("Symbol __start___lttng_callsites not defined.\n");
      return;
    }

  callsites_start = BMSYMBOL_VALUE_ADDRESS(callsites_start_sym);
  printf("callsites start: %s\n", paddress(arch, callsites_start));

  callsites_stop_sym = lookup_minimal_symbol("__stop___lttng_callsites", NULL, objfile);
  if (callsites_stop_sym.minsym == NULL)
    {
      printf("Symbol __stop___lttng_callsites not defined.\n");
      return;
    }

  callsites_stop = BMSYMBOL_VALUE_ADDRESS(callsites_stop_sym);
  printf("callsites stop: %s\n", paddress(arch, callsites_stop));

  p = callsites_start;
  while (p < callsites_stop)
    {
      struct probe *pr;
      int ret;
      const char *full_name;
      int bytes_read;
      CORE_ADDR tp_struct_addr, callsite_addr;
      char *provider, *name;

      printf("Reading name at %s\n", paddress (arch, p));

//
//      ret = extract_provider_name (full_name, &provider, &name);
//      if (ret != 0)
//	{
//	  printf("Error extracting provider/name from %s\n", full_name);
//	  break;
//	}
//
//      p += bytes_read;
      printf("Reading address at %s\n", paddress (arch, p));

      tp_struct_addr = read_memory_typed_address (p, ptr_type);
      printf("tp struct at %s\n", paddress (arch, tp_struct_addr));

      p += TYPE_LENGTH (ptr_type);

      callsite_addr = read_memory_typed_address (p, ptr_type);
      printf("Callsite of at %s\n", paddress (arch, callsite_addr));

      p += TYPE_LENGTH (ptr_type);

      full_name = read_tracepoint_name (tp_struct_addr, ptr_type, arch);
      if (full_name == NULL)
	{
	  printf("Couldn't read name\n");
	  continue;
	}

      extract_provider_name(full_name, &provider, &name);
      printf("name is %s %s\n", provider, name);

      pr = xmalloc (sizeof(struct probe));

      pr->address = callsite_addr;
      pr->arch = arch;
      pr->name = name;
      pr->pops = &lttng_probe_ops;
      pr->provider = provider;

      VEC_safe_push(probe_p, *probes, pr);

      p += TYPE_LENGTH(ptr_type);
    }
}

static const char *
lttng_type_name (struct probe *probe)
{
  gdb_assert (probe->pops == &lttng_probe_ops);
  return "lttng";
}

/* LTTng probe_ops.  */

const struct probe_ops lttng_probe_ops =
{
  lttng_is_linespec, //dtrace_probe_is_linespec,
  lttng_get_probes, //dtrace_get_probes,
  lttng_get_probe_address, //dtrace_get_probe_address,
  NULL, //dtrace_get_probe_argument_count,
  NULL, //dtrace_can_evaluate_probe_arguments,
  NULL, //dtrace_evaluate_probe_argument,
  NULL, //dtrace_compile_to_ax,
  NULL, /* set_semaphore  */
  NULL, /* clear_semaphore  */
  NULL, //dtrace_probe_destroy,
  lttng_type_name, //dtrace_type_name,
  NULL, //dtrace_gen_info_probes_table_header,
  NULL, //dtrace_gen_info_probes_table_values,
  NULL, //dtrace_enable_probe,
  NULL, //dtrace_disable_probe
};

/* Implementation of the `info probes lttng' command.  */

static void
info_probes_lttng_command (char *arg, int from_tty)
{
  info_probes_for_ops (arg, from_tty, &lttng_probe_ops);
}

void _initialize_lttng_probe (void);

void
_initialize_lttng_probe (void)
{
  VEC_safe_push (probe_ops_cp, all_probe_ops, &lttng_probe_ops);

  add_cmd ("lttng", class_info, info_probes_lttng_command,
	   _("\
Show information about LTTng static probes.\n\
Usage: info probes dtrace [PROVIDER [NAME [OBJECT]]]\n\
Each argument is a regular expression, used to select probes.\n\
PROVIDER matches probe provider names.\n\
NAME matches the probe names.\n\
OBJECT matches the executable or shared library name."),
	   info_probes_cmdlist_get ());
}
