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
#include <time.h>

#include "bakassabl.h"

#ifndef PROGNAME
#define PROGNAME "bakassabl"
#endif

#ifndef AUTHOR
#define AUTHOR "@_hugsy_"
#endif



typedef enum {
        false = 0,
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
bool_t gentle_mode = false;




/**
 *
 */
static int _lookup_syscall(const char* name)
{
        syscall_t *sc;

        for(sc=syscall_table; sc->syscall_name && sc->syscall_num>-1 ; sc++){
                if (strcmp(name, sc->syscall_name) == 0){
                        if (verbose)
                                printf("[+] Found syscall '%s' as %d\n", sc->syscall_name, sc->syscall_num);
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
                perror("[_init_nnp] Failed prctl");
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
                perror("[_init_seccomp] Failed to init default rule");
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
                perror("[apply_seccomp] Failed loading current context");
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
                                printf("[+] Enabling PARANOID mode\n");
                        return _init_nnp();

                case SECCOMP_PERMIT:
                        if (verbose)
                                printf("[+] Enabling PERMIT as default mode\n");
                        return _init_seccomp(SCMP_ACT_ALLOW);

                case SECCOMP_BLOCK:
                        if (verbose)
                                printf("[+] Enabling BLOCK as default mode\n");
                        return _init_seccomp(SCMP_ACT_KILL);

                default:
                        return -1;
        }
}


/**
 *
 */
static int add_rule(int mode, const char* r, unsigned int cnt, struct scmp_arg_cmp *args)
{
        int sc_num = -1;

        sc_num = _lookup_syscall(r);
        if ( sc_num < 0 ){
                printf("[-] Failed to find syscall '%s' (typo?)\n", r);
                return -1;
        }

        if (mode==SCMP_ACT_KILL && gentle_mode)
                mode = SCMP_ACT_ERRNO((uint16_t) -1);

        if ( seccomp_rule_add_array(ctx, mode, sc_num, cnt, args) < 0) {
                perror("[add_allow_rule] Failed adding rule");
                return -1;
        }

        return 0;
}


/**
 * Add black-listing rule
 */
static int add_simple_allow_rule(const char* scname)
{
        if (verbose)
                printf("[+] Allowing '%s'\n", scname);

        return add_rule(SCMP_ACT_ALLOW, scname, 0, NULL);
}


/**
 * Add white-listing rule
 */
static int add_simple_deny_rule(const char* scname)
{
        if (verbose)
                printf("[+] Denying '%s'\n", scname);

        return add_rule(SCMP_ACT_KILL, scname, 0, NULL);
}


/**
 * Add black-listing rule to block calls to socket(AF_INET, ...)
 */
static int add_no_internet_rule()
{
        // AF_INET = PF_INET = 2
        struct scmp_arg_cmp args[] = {
                SCMP_A0(SCMP_CMP_EQ, 2)
        };

        if (verbose)
                printf("[+] Denying 'socket(AF_INET, ...)'\n");

        return add_rule(SCMP_ACT_KILL, "socket", 1, args);
}


/**
 * Enable syscall fuzz mode: return a random value between [0, 2**16[
 * for all syscalls
 */
static int set_fuzz_mode()
{
        syscall_t *sc;

        if (verbose)
                printf("[+] Initializating fuzz mode'\n");

        srand(time(NULL));

        for(sc=syscall_table; sc->syscall_name && sc->syscall_num>-1 ; sc++){
                uint16_t random_value = rand() % ((1<<16)-1);

                if (verbose)
                        printf("[+] '%s()' -> #%d\n", sc->syscall_name, sc->syscall_num);

                seccomp_rule_add_array(ctx,
                                       SCMP_ACT_ERRNO(random_value),
                                       sc->syscall_num, 0, NULL);
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
 * Usage function
 */
static int usage(int retcode)
{
	FILE* fd;
	fd = (retcode == EXIT_SUCCESS) ? stdout : stderr;

	fprintf(fd,
                "%1$s (for %2$s) - written by %3$s\n"
                "\n"
                "Syntax:\n"
                "%1$s --allow-all [--deny privilege]* -- /path/to/my/program [--prog-arg]*\n"
                "or\n"
                "%1$s --deny-all  [--allow privilege]* -- /path/to/my/program [--prog-arg]*\n"
                "or\n"
                "%1$s --paranoid -- /path/to/my/program [--prog-arg]*\n"
                "\nList syscalls: "
                "%1$s --list-syscalls\n"
                ,
                PROGNAME, arch, AUTHOR);

        return retcode;
}


/**
 * Enumerate syscalls for the current architecture
 */
static void list_syscalls()
{
        syscall_t *sc;
        printf("System calls list downloaded from:\n");
        printf("[+] %s\n", syslist_src);

        printf("Supported syscalls for %s:\n", arch);
        for(sc=syscall_table; sc->syscall_name && sc->syscall_num>-1 ; sc++) {
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
		{ "help",                no_argument, 0, 'h' },
                { "list-syscalls",       no_argument, 0, 'l' },
                { "verbose",             no_argument, 0, 'v' },
                { "gentle",              no_argument, 0, 'g' },

                { "allow-all",           no_argument, 0, 'A' },
                { "deny",                required_argument, 0, 'd' },
                { "no-internet",         no_argument, 0, 'i' },
                { "fuzz-mode",           no_argument, 0, 'f' },

                { "deny-all",            no_argument, 0, 'D' },
                { "allow",               required_argument, 0, 'a' },

                { "paranoid",            no_argument, 0, 'P' },

		{ 0, 0, 0, 0 }
	};


        while (1) {
		curopt_idx = 0;
                curopt = getopt_long (argc,argv,"Aifd:Da:Phvgl",long_opts, &curopt_idx);
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
                                if (mode != SECCOMP_PERMIT){
                                        printf("[-] Invalid mode\n");
                                        return EXIT_FAILURE;
                                }

                                ret = add_simple_deny_rule(optarg);
                                if (ret < 0)
                                        goto out;
                                break;
                        case 'i':
                                if (mode != SECCOMP_PERMIT){
                                        printf("[-] Invalid mode\n");
                                        return EXIT_FAILURE;
                                }
                                add_no_internet_rule();
                                break;
                        case 'f':
                                if (mode != SECCOMP_PERMIT){
                                        printf("[-] Invalid mode\n");
                                        return EXIT_FAILURE;
                                }
                                set_fuzz_mode();
                                break;


                        case 'D':
                                ret = init_mode(SECCOMP_BLOCK);
                                if (ret < 0) {
                                        return EXIT_FAILURE;
                                }
                                break;
                        case 'a':
                                if (mode != SECCOMP_BLOCK){
                                        printf("[-] Invalid mode\n");
                                        return EXIT_FAILURE;
                                }

                                ret = add_simple_allow_rule(optarg);
                                if (ret < 0)
                                        goto out;
                                break;


                        case 'l':
                                list_syscalls();
                                return EXIT_SUCCESS;

                        case 'v':
                                verbose++;
                                break;

                        case 'g':
                                gentle_mode = true;
                                break;

                        case 'h':
                                return usage(EXIT_SUCCESS);

                        case '?':
                        default:
                                return usage(EXIT_FAILURE);
                }
        }

        if (mode == UNDEFINED) {
                printf("[-] No mode selected\n");
                goto out;
        }

        if (optind == argc) {
                printf("[-] Missing executable\n");
                goto out;
        }

        bin = argv[optind];
        args = &argv[optind];

        if (verbose){
                printf ("[+] Starting '%s", bin);
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
