#define COLOR_RED     "\e[31m"
#define COLOR_GREEN   "\e[32m"
#define COLOR_YELLOW  "\e[33m"
#define COLOR_BLUE    "\e[34m"
#define COLOR_MAGENTA "\e[35m"
#define COLOR_CYAN    "\001\e[36m\002"
#define COLOR_RESET   "\001\e[0m\002"

/* Cleanup to reset the terminal color.  */

struct cleanup *make_cleanup_reset_color (struct ui_file *stream);

/* Emit on STREAM the code to switch to COLOR.  */

void ui_file_color (struct ui_file *stream, const char *color);
