#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/prctl.h>
#include <string.h>

#define PR_SET_GLOBAL_BREAKPOINT        48
#define PR_GET_GLOBAL_BREAKPOINT        49
# define PR_GLOBAL_BREAKPOINT_EN        (1 << 0)
# define PR_GLOBAL_BREAKPOINT_FORK      (1 << 1)
# define PR_GLOBAL_BREAKPOINT_EN_FORK   (PR_GLOBAL_BREAKPOINT_EN | \
		                PR_GLOBAL_BREAKPOINT_FORK)

const int FLAG_MODE = 'm';
const char *mode_fork_only = "fork";
const char *mode_self_only = "self";
const char *mode_both = "both";

static void usage(void)
{
	printf("Usage: gbp-wrapper [options] executable [executable arguments]\n");
	printf("\n");
	printf("  gbp-wrapper starts an executable with global breakpoints enabled.\n");
}

void execute(char *argv[])
{
	/* Allocate one more for NULL */
	execvp(argv[0], argv);
	perror(argv[0]);
}

int main(int argc, char *argv[])
{
	int c, ret;
	int prctl_val = PR_GLOBAL_BREAKPOINT_EN_FORK;
	struct option long_options[] = {
		{"mode", 1, NULL, FLAG_MODE},
		{NULL, 0, NULL, 0},
	};

	if (argc < 2) {
		usage();
		return 0;
	}

	while ((c = getopt_long(argc, argv, "+m:", long_options, NULL))) {
		if (c == -1) {
			break;
		}

		if (c == '?') {
			/* Unknown switch, getopt prints an error message for us. */
			return 1;
		}

		if (c == 'm') {
			if (strcmp(optarg, mode_fork_only) == 0) {
				prctl_val = PR_GLOBAL_BREAKPOINT_FORK;
			} else if (strcmp(optarg, mode_self_only) == 0) {
				prctl_val = PR_GLOBAL_BREAKPOINT_EN;
			} else if (strcmp(optarg, mode_both) == 0) {
				/* Nothing to do, it's the default. */
			} else {
				fprintf(stderr, "Invalid value for [-m|--mode]: %s\n", optarg);
				return 1;
			}
		}
	}

	if (optind == argc) {
		usage();
		return 0;
	}

	ret = prctl(PR_SET_GLOBAL_BREAKPOINT, prctl_val, 0, 0, 0);
	if (ret) {
		fprintf(stderr, "error: prctl returned %d.\n", ret);
		return 1;
	}

	execute(argv + optind);

	/* If we reach here, it is an error. */
	return 1;
}
