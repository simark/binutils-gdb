#include <defs.h>
#include <color.h>
#include <command.h>
#include <gdbcmd.h>


static enum auto_boolean colors_enabled = AUTO_BOOLEAN_AUTO;

static void
cleanup_reset_color (void *arg)
{
  struct ui_file *uf = arg;

  fprintf_unfiltered(uf, COLOR_RESET);
}

struct cleanup *
make_cleanup_reset_color (struct ui_file *stream)
{
  return make_cleanup (cleanup_reset_color, stream);
}

void
ui_file_color (struct ui_file *stream, const char *color)
{
  fprintf_unfiltered(stream, "%s", color);
}

void _initialize_color (void);

void
_initialize_color (void)
{
	add_setshow_auto_boolean_cmd("colors", class_support, &colors_enabled,
			"Set whether to use color in the CLI.",
			"Show whether usage of colors in the CLI is enabled.",
			NULL,
			NULL, NULL, &setlist, &showlist);
}
