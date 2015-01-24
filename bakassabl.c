/**
 * Basic (one file) sandboxer using seccomp
 *
 * @_hugsy_
 */

#include <stdio.h>
#include <stdlib.h>
#include <seccomp.h>
#include <errno.h>
#include <unistd.h>

#define PROGNAME "bakassabl"


scmp_filter_ctx ctx = NULL;


/**
 *
 */
void init_sandbox()
{
        ctx = seccomp_init( SCMP_ACT_ALLOW );
        if (!ctx) {
                perror("failed to init seccomp");
                abort();
        }

        if ( seccomp_load(ctx) ){
                perror("failed loading rule");
                abort();
        }

        return;
}


/**
 *
 */
static int add_allow_rule()
{
        return 0;
}


/**
 *
 */
static int add_deny_rule()
{
        if ( seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(connect), 0) ) {
                perror("failed adding rule");
                return -1;
        }

        return 0;
}


/**
 * if here, it means an error occured earlier
 * always return in error
 */
static int release_sandbox()
{
        seccomp_release(ctx);
        return -1;
}


/**
 *
 */
void usage(int retcode)
{
	FILE* fd;
	fd = (retcode == 0) ? stdout : stderr;

	fprintf(fd,
                "SYNTAX:\n"
                "%s --allow-all [--deny privilege]* -- /path/to/my/program [--prog-arg]*\n",
                "\tor\n"
                "%s --deny-all  [--allow privilege]* -- /path/to/my/program [--prog-arg]*\n",
                "\tor\n"
                "%s --parano -- /path/to/my/program [--prog-arg]*\n",
                PROGNAME, PROGNAME, PROGNAME );

        return retcode;
}


/**
 * main function
 */
int main(int argc, char** argv, char** envp)
{
	int ret, i;
        char *bin, **args;
        void** func;

        struct option long_opts[] = {
		{ "help",       0, 0, 'h' },
		{ "verbose",    0, 0, 'v' },

                { "allow-all",  0, 0, 0 },
                { "deny",       1, 0, 0 },

                { "deny-all",    0, 0, 0 },
                { "allow",       1, 0, 0 },

		{ 0, 0, 0, 0 }
	};

        while (1) {
		curopt_idx = 0;
                curopt = getopt_long (argc,argv,"hv",long_opts, &curopt_idx);
		if (curopt == -1) break;
		switch (curopt) {

                        /* case */

                        case 'h':
                        case '?':
                        default:
                                usage(EXIT_FAILURE);
                }
        }

        bin = argv[1];
        args = &argv[1];

        if (execve(bin, args, envp) < 0)
                perror("execve");

        if (use_seccomp)

	return EXIT_FAILURE;
}
