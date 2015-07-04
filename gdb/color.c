#include <defs.h>
#include <command.h>
#include <gdbcmd.h>

static enum auto_boolean colors_enabled = AUTO_BOOLEAN_AUTO;

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
