#include "defs.h"
#include "index-cache.h"
#include "dwarf2-index.h"
#include "cli/cli-cmds.h"
#include "command.h"
#include "objfiles.h"
#include "build-id.h"
#include <string>
#include <sys/mman.h>
#include "selftest.h"

static int debug_index_cache = 0;
static char *index_cache_directory = NULL;
index_cache global_index_cache;

/* A cheap (as in low-quality) recursive mkdir.  Try to create all the parents
   directories up to DIR and DIR itself.  Stop if we hit an error along the way.
   There is no attempt to remove created directories in case of failure.  */

static void
mkdir_recursive (const char *dir)
{
  /* This function only deals with absolute paths.  */
  gdb_assert (*dir == '/');

  gdb::unique_xmalloc_ptr<char> holder (xstrdup (dir));
  char * const start = holder.get ();
  char *component_start = start;
  char *component_end = start;

  while (1)
    {
      /* Find the beginning of the next component.  */
      while (*component_start == '/')
	component_start++;

      /* Are we done?  */
      if (*component_start == '\0')
	return;

      /* Find the slash or null-terminator after this component.  */
      component_end = component_start;
      while (*component_end != '/' && *component_end != '\0')
	component_end++;

      /* Temporarily replace the slash with a null terminator, so we can create
         the directory up to this component.  */
      char saved_char = *component_end;
      *component_end = '\0';

      /* If we get EEXIST and the existing path is a directory, then we're
         happy.  If it exists, but it's a regular file and this is not the last
         component, we'll fail at the next component.  If this is the last
         component, the caller will fail with ENOTDIR when trying to
         open/create a file under that path.  */
      if (mkdir (start, 0700) != 0)
	if (errno != EEXIST)
	  return;

      /* Restore the overwritten char.  */
      *component_end = saved_char;
      component_start = component_end;
    }
}

/* Get the standard cache directory for the current platform.  */

static char *
get_standard_cache_dir ()
{
#ifdef __linux__

  char *xdg_cache_home = getenv ("XDG_CACHE_HOME");

  if (xdg_cache_home != NULL)
    return xstrprintf ("%s/gdb", xdg_cache_home);

  char *home = getenv ("HOME");

  if (home != NULL)
    return xstrprintf ("%s/.cache/gdb", home);

  return NULL;

#else
#error "Platform not recognized, please add support for it."
#endif
}

void
index_cache::set_directory (const char *dir)
{
  gdb_assert (dir != NULL);
  gdb_assert (dir[0] != '\0');

  m_dir = dir;

  if (debug_index_cache)
    printf_filtered ("Index cache now using directory %s\n", m_dir);
}

void
index_cache::enable ()
{
  if (debug_index_cache)
    printf_filtered ("Enabling index cache (%s).\n", m_dir);

  m_enabled = true;
}

void
index_cache::disable ()
{
  if (debug_index_cache)
    printf_filtered ("Disabling index cache.\n");

  m_enabled = false;
}

/* See index-cache.h.  */

void
index_cache::store (struct dwarf2_per_objfile *dwarf2_per_objfile)
{
  if (!enabled ())
    return;

  TRY
    {
      struct objfile *objfile = dwarf2_per_objfile->objfile;
      std::string cache_filename = make_cache_filename (objfile);

      mkdir_recursive (m_dir);

      if (debug_index_cache)
        printf_filtered ("Saving index to cache at %s\n", cache_filename.c_str ());

      write_psymtabs_to_index (dwarf2_per_objfile, cache_filename.c_str ());
    }
  CATCH (except, RETURN_MASK_ERROR)
    {
      if (debug_index_cache)
	printf_filtered ("index cache error: %s\n", except.message);
    }
  END_CATCH
}

bool
index_cache::read (struct dwarf2_per_objfile *dwarf2_per_objfile,
		   const char *filename,
		   int deprecated_ok,
		   struct mapped_index *map,
		   const gdb_byte **cu_list,
		   offset_type *cu_list_elements,
		   const gdb_byte **types_list,
		   offset_type *types_list_elements)
{
  if (!enabled ())
    return false;

  TRY
    {
      struct objfile *objfile = dwarf2_per_objfile->objfile;
      std::string filename = make_cache_filename (objfile);

      if (debug_index_cache)
        printf("Reading index from cache from %s\n", filename.c_str ());

      mmap_file f (filename.c_str ());
      gdb::array_view<gdb_byte> buffer ((gdb_byte *) f.addr (), f.size ());

      bool success =  read_index_from_buffer (filename.c_str (),
				     deprecated_ok, buffer, map, cu_list,
				     cu_list_elements, types_list,
				     types_list_elements);

      if (success)
	{
	  dwarf2_per_objfile->index_mmap.emplace (std::move (f));
	  m_n_hits++;
	}
      else
	m_n_misses++;

      return success;
    }
  CATCH (except, RETURN_MASK_ERROR)
    {
      if (debug_index_cache)
	printf_filtered ("index cache error: %s\n", except.message);
      m_n_misses++;
    }
  END_CATCH

  return false;
}

/* See index-cache.h.  */

std::string
index_cache::make_cache_filename (struct objfile *objfile)
{
  const bfd_build_id *build_id = build_id_bfd_get (objfile->obfd);

  if (build_id == NULL)
    error ("objfile has no build-id");

  std::string build_id_str = build_id_to_string (build_id);

  return string_printf ("%s/%s%s", m_dir, build_id_str.c_str (), INDEX_SUFFIX);
}

static cmd_list_element *set_index_cache_prefix_list;
static cmd_list_element *show_index_cache_prefix_list;

static void
set_index_cache_command (const char *arg, int from_tty)
{
  printf_filtered ("\
Missing arguments.  See \"help set index-cache\" for help.\n");
}

static bool in_show_index_cache_command = false;

static void
show_index_cache_command (const char *arg, int from_tty)
{
  auto restore_flag = make_scoped_restore (&in_show_index_cache_command,
					   true);

  cmd_show_list (show_index_cache_prefix_list, from_tty, "");

  printf_filtered ("\n");
  printf_filtered ("The index cache is currently %s.\n",
		   global_index_cache.enabled () ? "enabled" : "disabled");
}

static void
set_index_cache_on_command (const char *arg, int from_tty)
{
  global_index_cache.enable ();
}

static void
set_index_cache_off_command (const char *arg, int from_tty)
{
  global_index_cache.disable ();
}

static void
set_index_cache_directory_command (const char *arg, int from_tty,
				   cmd_list_element *element)
{
  global_index_cache.set_directory (index_cache_directory);
}

static void
show_index_cache_stats_command (const char *arg, int from_tty)
{
  const char *indent = "";

  /* If this command is invoked through "show index-cache", make the display a
     bit nicer.  */
  if (in_show_index_cache_command)
    {
      indent = "  ";
      printf_filtered ("\n");
    }

  printf_filtered ("%s  Cache hits (this session): %u\n",
		   indent, global_index_cache.n_hits ());
  printf_filtered ("%sCache misses (this session): %u\n",
		   indent, global_index_cache.n_misses ());
}

#if GDB_SELF_TEST
namespace selftests
{
static bool
create_dir_and_check (const std::string &dir)
{
  mkdir_recursive (dir.c_str ());

  struct stat st;
  if (stat (dir.c_str (), &st) != 0)
    perror_with_name ("stat");

  return (st.st_mode & S_IFDIR) != 0;
}

static void
test_mkdir_recursive ()
{
  gdb::unique_xmalloc_ptr<char> base (xstrdup ("/tmp/gdb-selftests-XXXXXX"));

  if (mkdtemp (base.get ()) == NULL)
    perror_with_name ("mkdtemp");

  std::string dir = string_printf ("%s/a/b", base.get ());
  SELF_CHECK (create_dir_and_check (dir));

  dir = string_printf ("%s/a/b/c//d/e/", base.get ());
  SELF_CHECK (create_dir_and_check (dir));
}
}
#endif

void
_initialize_index_cache ()
{
  /* Set the default index cache directory.  */
  index_cache_directory = get_standard_cache_dir ();
  if (index_cache_directory != NULL)
    global_index_cache.set_directory (index_cache_directory);

  /* set index-cache */
  add_prefix_cmd ("index-cache", class_files, set_index_cache_command,
		  _("Set index-cache options"), &set_index_cache_prefix_list,
		  "set index-cache ", false, &setlist);

  /* show index-cache */
  add_prefix_cmd ("index-cache", class_files, show_index_cache_command,
		  _("Show index-cache options"), &show_index_cache_prefix_list,
		  "show index-cache ", false, &showlist);

  /* set index-cache on */
  add_cmd ("on", class_files, set_index_cache_on_command,
	   _("Enable the index cache."), &set_index_cache_prefix_list);

  /* set index-cache off */
  add_cmd ("off", class_files, set_index_cache_off_command,
	   _("Disable the index cache."), &set_index_cache_prefix_list);

  /* set index-cache directory */
  add_setshow_filename_cmd ("directory", class_files, &index_cache_directory,
			    _("Set the directory of the index cache."),
			    _("Show the directory of the index cache."),
			    NULL,
			    set_index_cache_directory_command, NULL,
			    &set_index_cache_prefix_list,
			    &show_index_cache_prefix_list);

  add_cmd ("stats", class_files, show_index_cache_stats_command,
	   _("Show some stats about the index cache."),
	   &show_index_cache_prefix_list);

  add_setshow_boolean_cmd ("index-cache", class_maintenance,
			   &debug_index_cache,
			   _("Set display of index-cache debug messages."),
			   _("Show display of index-cache debug messages."),
			   _("\
When non-zero, debugging output for the index cache is displayed."),
			    NULL, NULL,
			    &setdebuglist, &showdebuglist);
#if GDB_SELF_TEST
  selftests::register_test ("mkdir_recursive", selftests::test_mkdir_recursive);
#endif
}

