/**
 * bakassabl : a basic (one file) sandboxer using seccomp
 *
 * @_hugsy_
 *
 * Compile:
 * $ make
 *
 * Examples:
 * $ ./bakassabl --verbose --paranoid  -- /bin/ping -c 10 localhost
 * $ ./bakassabl --verbose --allow-all --deny connect -- /usr/bin/ncat -v4 localhost 22
 * $ ./bakassabl --verbose --allow-all --deny connect -- /bin/cat /etc/passwd
 * $ ./bakassabl --verbose --deny-all  --allow exit -- ./myexit
 *
 * ToDo:
 * deny-all mode is not fully operational
 * create group (ex: file=(open|read|write|close|stat|access), etc.)
 * add argument filters
 */


#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <seccomp.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/prctl.h>

#include "bakassabl.h"

#ifndef PROGNAME
#define PROGNAME "bakassabl"
#endif

#ifndef AUTHOR
#define AUTHOR "@_hugsy_"
#endif

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
 *
 */
static int _lookup_syscall(const char* name)
{
        syscall_t *sc;

        for(sc=syscall_table; sc->syscall_name && sc->syscall_num>-1 ; sc++){
                if (strcmp(name, sc->syscall_name) == 0){
                        if (verbose)
                                printf("[+] found syscall '%s' as %d\n", sc->syscall_name, sc->syscall_num);
                        return sc->syscall_num;
                }
        }

        return -1;
}


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

        return 0;
}


/**
 *
 */
static int apply_seccomp()
{
        if ( seccomp_load(ctx) < 0){
                perror("[apply_seccomp] failed loading current context");
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
static int add_rule(sandbox_mode_t m, const char* r)
{
        int sc_num = -1;

        if (mode != m) {
                printf("[-] invalid mode, cannot proceed\n");
                return -1;
        }

        sc_num = _lookup_syscall(r);
        if ( sc_num < 0 ){
                printf("[-] failed to find syscall '%s' (typo?)\n", r);
                return -1;
        }

        if ( seccomp_rule_add(ctx, (m==SECCOMP_BLOCK?SCMP_ACT_ALLOW:SCMP_ACT_KILL), sc_num, 0) < 0) {
                perror("[add_allow_rule] failed adding rule");
                return -1;
        }

        if (verbose) {
                printf("[+] %s '%s'\n",
                       m==SECCOMP_BLOCK?"allowing":"denying",
                       r);
        }

        return 0;
}


/**
 * Add black-listing rule
 */
static int add_allow_rule(const char* rule)
{
        return add_rule(SECCOMP_BLOCK, rule);
}


/**
 * Add white-listing rule
 */
static int add_deny_rule(const char* rule)
{
        return add_rule(SECCOMP_PERMIT, rule);
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
 * Usage function
 */
static int usage(int retcode)
{
	FILE* fd;
	fd = (retcode == EXIT_SUCCESS) ? stdout : stderr;

	fprintf(fd,
                "%s (for %s) - written by %s\n"
                "\n"
                "Syntax:\n"
                "%s --allow-all [--deny privilege]* -- /path/to/my/program [--prog-arg]*\n"
                "\tor\n"
                "%s --deny-all  [--allow privilege]* -- /path/to/my/program [--prog-arg]*\n"
                "\tor\n"
                "%s --paranoid -- /path/to/my/program [--prog-arg]*\n",
                PROGNAME, arch, AUTHOR,
                PROGNAME, PROGNAME, PROGNAME );

        return retcode;
}


/**
 * Enumerate syscalls for the current architecture
 */
static void list_syscalls()
{
        syscall_t *sc;
        printf("Syscall list downloaded from:\n");
        printf("[+] %s\n", syslist_src);

        printf("Supported syscalls for %s:\n", arch);
        for(sc=syscall_table; sc->syscall_name && sc->syscall_num>-1 ; sc++){
                printf("[+] %d : '%s'\n", sc->syscall_num, sc->syscall_name);
        }
        return;
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
                { "list",       no_argument, 0, 'l' },
                { "verbose",    no_argument, 0, 'v' },
                { "quiet",      no_argument, 0, 'q' },

                { "allow-all",  no_argument, 0, 'A' },
                { "deny",       required_argument, 0, 'd' },

                { "deny-all",   no_argument, 0, 'D' },
                { "allow",      required_argument, 0, 'a' },

                { "paranoid",   no_argument, 0, 'P' },

		{ 0, 0, 0, 0 }
	};

        while (1) {
		curopt_idx = 0;
                curopt = getopt_long (argc,argv,"Ad:Da:Phvql",long_opts, &curopt_idx);
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


                        case 'l':
                                list_syscalls();
                                return EXIT_SUCCESS;

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

        if (mode != UNDEFINED && mode != PARANOID)
                apply_seccomp();

        if (execve(bin, args, envp) < 0)
                perror("execve");

out:
        if (mode != UNDEFINED && mode != PARANOID)
                release_sandbox();

	return EXIT_FAILURE;
}
