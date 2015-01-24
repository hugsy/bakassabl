/**
 * bakassabl : a basic (one file) sandboxer using seccomp
 *
 * @_hugsy_
 *
 * Compile:
 * $ cc -o bakassabl -Werror -O3 -fPIE -fPIC -fstack-protector-all -Wl,-z,relro bakassabl.c -lseccomp -pie
 *
 * Examples:
 * $ ./bakassabl --verbose --paranoid  -- /bin/ping -c 10 localhost
 * $ ./bakassabl --verbose --allow-all --deny connect -- /usr/bin/ncat -v4 localhost 22
 * $ ./bakassabl --verbose --deny-all  --allow exit -- ./myexit
 */


#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <seccomp.h>
#include <errno.h>
#include <unistd.h>
#include <sys/prctl.h>

#define PROGNAME "bakassabl"

typedef enum {
        false,
        true
} bool_t;

typedef enum {
        UNDEFINED = -1,
        SECCOMP_PERMIT = 0,
        SECCOMP_BLOCK,
        PARANOID
} sandbox_mode_t;


scmp_filter_ctx ctx = NULL;
sandbox_mode_t mode = UNDEFINED;
int verbose = 0;


/**
 * Set the NO_NEW_PRIVS to the process
 */
static int _init_nnp()
{
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
                perror("[_init_nnp] failed prctl");
                return -1;
        }
        return 0;
}


/**
 *
 */
static int _init_seccomp(uint32_t seccomp_type)
{
        ctx = seccomp_init(seccomp_type);
        if (!ctx) {
                perror("[_init_seccomp] failed to init default rule");
                return -1;
        }

        if ( seccomp_load(ctx) < 0){
                perror("[_init_seccomp] failed loading context");
                return -1;
        }

        return 0;
}


/**
 *
 */
static int init_mode(sandbox_mode_t type)
{
        if (mode != UNDEFINED){
                printf("[-] A mode has already been defined.\n");
                return -1;
        }

        mode = type;

        switch(mode) {
                case PARANOID:
                        if (verbose)
                                printf("[+] enabling PARANOID mode\n");
                        return _init_nnp();

                case SECCOMP_PERMIT:
                        if (verbose)
                                printf("[+] enabling PERMIT as default mode\n");
                        return _init_seccomp(SCMP_ACT_ALLOW);

                case SECCOMP_BLOCK:
                        if (verbose)
                                printf("[+] enabling BLOCK as default mode\n");
                        return _init_seccomp(SCMP_ACT_KILL);

                default:
                        return -1;
        }
}


/**
 *
 */
static int add_allow_rule(const char* rule)
{
        if (mode != SECCOMP_BLOCK) {
                printf("invalid mode, cannot proceed\n");
                return -1;
        }

        if ( seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0) < 0) {
                perror("[add_allow_rule] failed adding rule");
                return -1;
        }

        if (verbose)
                printf("[+] allowing '%s'\n", rule);


        return 0;
}


/**
 *
 */
static int add_deny_rule(const char* rule)
{
        if (mode != SECCOMP_PERMIT) {
                printf("invalid mode, cannot proceed\n");
                return -1;
        }

        if ( seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(connect), 0) < 0) {
                perror("[add_deny_rule] failed adding rule");
                return -1;
        }

        if (verbose)
                printf("[+] denying '%s'\n", rule);

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
static int usage(int retcode)
{
	FILE* fd;
	fd = (retcode == EXIT_SUCCESS) ? stdout : stderr;

	fprintf(fd,
                "SYNTAX:\n"
                "%s --allow-all [--deny privilege]* -- /path/to/my/program [--prog-arg]*\n"
                "\tor\n"
                "%s --deny-all  [--allow privilege]* -- /path/to/my/program [--prog-arg]*\n"
                "\tor\n"
                "%s --paranoid -- /path/to/my/program [--prog-arg]*\n",
                PROGNAME, PROGNAME, PROGNAME );

        return retcode;
}


/**
 * main function
 */
int main(int argc, char** argv, char** envp)
{
	int ret;
        char *bin, **args;
        int curopt_idx;
        int curopt;
        bool_t do_loop = true;

        struct option long_opts[] = {
		{ "help",       no_argument, 0, 'h' },
		{ "verbose",    no_argument, 0, 'v' },
                { "quiet",    no_argument, 0, 'q' },

                { "allow-all",  no_argument, 0, 'A' },
                { "deny",       required_argument, 0, 'd' },

                { "deny-all",   no_argument, 0, 'D' },
                { "allow",      required_argument, 0, 'a' },

                { "paranoid",   no_argument, 0, 'P' },

		{ 0, 0, 0, 0 }
	};

        while (1) {
		curopt_idx = 0;
                curopt = getopt_long (argc,argv,"Ad:Da:Phvq",long_opts, &curopt_idx);
		if (curopt == -1)
                        break;

		switch (curopt) {
                        case 'P':
                                ret = init_mode(PARANOID);
                                if (ret < 0){
                                        return EXIT_FAILURE;
                                }
                                break;

                        case 'A':
                                ret = init_mode(SECCOMP_PERMIT);
                                if (ret < 0){
                                        return EXIT_FAILURE;
                                }
                                break;
                        case 'd':
                                if (mode == UNDEFINED){
                                        printf("[-] A mode MUST be defined first\n");
                                        return EXIT_FAILURE;
                                }

                                ret = add_deny_rule(optarg);
                                if (ret < 0)
                                        goto out;
                                break;

                        case 'D':
                                ret = init_mode(SECCOMP_BLOCK);
                                if (ret < 0) {
                                        return EXIT_FAILURE;
                                }
                                break;
                        case 'a':
                                if (mode == UNDEFINED){
                                        printf("[-] A mode MUST be defined first\n");
                                        return EXIT_FAILURE;
                                }

                                ret = add_allow_rule(optarg);
                                if (ret < 0)
                                        goto out;
                                break;


                        case 'v':
                                verbose++;
                                break;

                        case 'q':
                                verbose = 0;
                                break;

                        case 'h':
                                return usage(EXIT_SUCCESS);

                        case '?':
                        default:
                                return usage(EXIT_FAILURE);
                }
        }

        if (mode == UNDEFINED) {
                printf("[-] no mode selected\n");
                goto out;
        }

        if (optind == argc) {
                printf("[-] missing executable\n");
                goto out;
        }

        bin = argv[optind];
        args = &argv[optind];

        if (verbose){
                printf ("[+] starting '%s", bin);
                for (int i=optind+1; i<argc; i++)
                        printf (" %s", argv[i]);
                printf("'\n");
        }

        if (execve(bin, args, envp) < 0)
                perror("execve");

out:
        if (mode != UNDEFINED && mode != PARANOID)
                release_sandbox();

	return EXIT_FAILURE;
}
