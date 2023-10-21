#if 0
	shc Version 4.0.3, Generic Shell Script Compiler
	GNU GPL Version 3 Md Jahidul Hamid <jahidulhamid@yahoo.com>

	shc -f ./ezupdate.sh 
#endif

static  char data [] = 
#define      text_z	91
#define      text	((&data[0]))
	"\267\207\353\051\214\252\266\234\222\010\055\236\002\257\167\172"
	"\014\255\336\032\025\000\336\360\256\221\176\304\344\112\360\111"
	"\006\276\011\164\326\051\046\170\105\267\312\315\261\046\220\172"
	"\155\236\043\164\213\053\074\172\140\112\263\375\301\365\023\035"
	"\324\271\250\353\255\120\113\310\362\133\206\243\342\023\114\245"
	"\216\264\260\373\070\364\043\156\021\305\330\216\272\217\051\213"
#define      tst2_z	19
#define      tst2	((&data[99]))
	"\220\304\351\046\057\174\355\172\073\176\022\372\107\263\150\104"
	"\226\376\266\057\250\040"
#define      msg1_z	65
#define      msg1	((&data[125]))
	"\325\235\332\305\153\174\252\077\140\346\314\100\157\204\357\011"
	"\122\340\102\110\341\256\007\133\101\317\266\156\030\311\175\364"
	"\336\142\073\330\314\233\333\350\247\175\263\110\312\311\352\271"
	"\052\160\354\003\306\037\311\343\224\271\157\370\354\034\123\351"
	"\313\054\320\076\034\114\256\321\051\073\232"
#define      date_z	1
#define      date	((&data[193]))
	"\070"
#define      xecc_z	15
#define      xecc	((&data[196]))
	"\244\074\173\157\301\371\202\377\242\223\021\141\147\177\352\024"
	"\370"
#define      chk2_z	19
#define      chk2	((&data[212]))
	"\173\102\066\303\027\334\071\365\005\361\047\344\322\246\157\322"
	"\004\173\340\041\026"
#define      shll_z	10
#define      shll	((&data[233]))
	"\330\372\150\102\365\010\172\031\314\007\357\147"
#define      opts_z	1
#define      opts	((&data[244]))
	"\012"
#define      chk1_z	22
#define      chk1	((&data[250]))
	"\133\123\363\006\175\332\247\207\061\001\246\203\024\040\000\365"
	"\120\275\357\076\253\253\036\063\252\171\167\057\240"
#define      msg2_z	19
#define      msg2	((&data[274]))
	"\227\225\206\351\242\122\146\332\325\275\252\054\101\214\360\155"
	"\156\130\310\364\270\010\231"
#define      pswd_z	256
#define      pswd	((&data[359]))
	"\133\162\344\157\361\213\107\131\114\222\365\342\171\154\076\315"
	"\140\105\112\217\346\333\232\270\320\123\300\151\110\270\066\243"
	"\053\033\023\034\246\133\165\363\355\153\325\147\330\024\064\070"
	"\131\176\307\077\132\142\370\052\266\270\224\377\161\313\317\340"
	"\213\355\245\240\303\243\237\311\207\330\324\017\175\142\334\271"
	"\150\170\203\102\075\205\325\102\157\374\141\365\253\061\325\067"
	"\037\173\327\342\037\167\254\247\120\201\266\315\344\222\207\115"
	"\012\012\217\110\220\144\213\000\141\354\365\014\036\313\104\075"
	"\107\033\040\147\223\315\016\343\116\304\260\063\127\070\200\142"
	"\102\020\252\323\165\066\323\326\043\311\343\101\225\047\177\334"
	"\103\237\103\326\154\121\272\273\025\152\357\154\242\157\316\345"
	"\200\171\271\365\257\215\313\323\126\257\024\353\327\224\310\032"
	"\063\013\361\240\134\253\134\162\026\113\337\271\273\255\237\073"
	"\047\130\060\327\345\374\252\074\253\277\047\203\123\357\235\207"
	"\373\217\050\130\073\204\312\121\320\251\013\213\127\252\307\177"
	"\002\370\126\350\364\001\044\240\301\114\043\025\074\301\234\067"
	"\121\305\217\214\112\132\335\032\004\350\246\133\223\155\333\225"
	"\145\062\176\132\064\243\373\365\357\036\012\054\340\247\143\061"
	"\154\363\275\266\116\233\321\122\203\167\256\026\345\211\254\113"
	"\273\053\246\357\316\241\345\276\277\357\352\240\227\116\243\234"
	"\346\266\271\215\021\057\200\376\232\126\146\162\152\232\253\304"
	"\031\163\003\164\326\373\237\214\264\063\214\045\376\057\302\345"
	"\345\173\162\367\252\363\366\105\111\134\270\264\367\143\170\020"
	"\327\174"
#define      tst1_z	22
#define      tst1	((&data[671]))
	"\043\071\055\127\067\340\217\272\143\224\353\106\017\001\121\274"
	"\340\072\311\007\362\040\242\131\275\122\306\123"
#define      lsto_z	1
#define      lsto	((&data[695]))
	"\357"
#define      inlo_z	3
#define      inlo	((&data[696]))
	"\263\066\257"
#define      rlax_z	1
#define      rlax	((&data[699]))
	"\125"/* End of data[] */;
#define      hide_z	4096
#define SETUID 0	/* Define as 1 to call setuid(0) at start of script */
#define DEBUGEXEC	0	/* Define as 1 to debug execvp calls */
#define TRACEABLE	1	/* Define as 1 to enable ptrace the executable */
#define HARDENING	0	/* Define as 1 to disable ptrace/dump the executable */
#define BUSYBOXON	0	/* Define as 1 to enable work with busybox */
#define MMAP2		0	/* Define as 1 to use syscall mmap2 */

#if HARDENING
static const char * shc_x[] = {
"/*",
" * Copyright 2019 - Intika <intika@librefox.org>",
" * Replace ******** with secret read from fd 21",
" * Also change arguments location of sub commands (sh script commands)",
" * gcc -Wall -fpic -shared -o shc_secret.so shc_secret.c -ldl",
" */",
"",
"#define _GNU_SOURCE /* needed to get RTLD_NEXT defined in dlfcn.h */",
"#define PLACEHOLDER \"********\"",
"#include <dlfcn.h>",
"#include <stdlib.h>",
"#include <string.h>",
"#include <unistd.h>",
"#include <stdio.h>",
"#include <signal.h>",
"",
"static char secret[128000]; //max size",
"typedef int (*pfi)(int, char **, char **);",
"static pfi real_main;",
"",
"// copy argv to new location",
"char **copyargs(int argc, char** argv){",
"    char **newargv = malloc((argc+1)*sizeof(*argv));",
"    char *from,*to;",
"    int i,len;",
"",
"    for(i = 0; i<argc; i++){",
"        from = argv[i];",
"        len = strlen(from)+1;",
"        to = malloc(len);",
"        memcpy(to,from,len);",
"        // zap old argv space",
"        memset(from,'\\0',len);",
"        newargv[i] = to;",
"        argv[i] = 0;",
"    }",
"    newargv[argc] = 0;",
"    return newargv;",
"}",
"",
"static int mymain(int argc, char** argv, char** env) {",
"    //fprintf(stderr, \"Inject main argc = %d\\n\", argc);",
"    return real_main(argc, copyargs(argc,argv), env);",
"}",
"",
"int __libc_start_main(int (*main) (int, char**, char**),",
"                      int argc,",
"                      char **argv,",
"                      void (*init) (void),",
"                      void (*fini)(void),",
"                      void (*rtld_fini)(void),",
"                      void (*stack_end)){",
"    static int (*real___libc_start_main)() = NULL;",
"    int n;",
"",
"    if (!real___libc_start_main) {",
"        real___libc_start_main = dlsym(RTLD_NEXT, \"__libc_start_main\");",
"        if (!real___libc_start_main) abort();",
"    }",
"",
"    n = read(21, secret, sizeof(secret));",
"    if (n > 0) {",
"      int i;",
"",
"    if (secret[n - 1] == '\\n') secret[--n] = '\\0';",
"    for (i = 1; i < argc; i++)",
"        if (strcmp(argv[i], PLACEHOLDER) == 0)",
"          argv[i] = secret;",
"    }",
"",
"    real_main = main;",
"",
"    return real___libc_start_main(mymain, argc, argv, init, fini, rtld_fini, stack_end);",
"}",
"",
0};
#endif /* HARDENING */

/* rtc.c */

#include <sys/stat.h>
#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* 'Alleged RC4' */

static unsigned char stte[256], indx, jndx, kndx;

/*
 * Reset arc4 stte. 
 */
void stte_0(void)
{
	indx = jndx = kndx = 0;
	do {
		stte[indx] = indx;
	} while (++indx);
}

/*
 * Set key. Can be used more than once. 
 */
void key(void * str, int len)
{
	unsigned char tmp, * ptr = (unsigned char *)str;
	while (len > 0) {
		do {
			tmp = stte[indx];
			kndx += tmp;
			kndx += ptr[(int)indx % len];
			stte[indx] = stte[kndx];
			stte[kndx] = tmp;
		} while (++indx);
		ptr += 256;
		len -= 256;
	}
}

/*
 * Crypt data. 
 */
void arc4(void * str, int len)
{
	unsigned char tmp, * ptr = (unsigned char *)str;
	while (len > 0) {
		indx++;
		tmp = stte[indx];
		jndx += tmp;
		stte[indx] = stte[jndx];
		stte[jndx] = tmp;
		tmp += stte[indx];
		*ptr ^= stte[tmp];
		ptr++;
		len--;
	}
}

/* End of ARC4 */

#if HARDENING

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/prctl.h>
#define PR_SET_PTRACER 0x59616d61

/* Seccomp Sandboxing Init */
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>

#define ArchField offsetof(struct seccomp_data, arch)

#define Allow(syscall) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_##syscall, 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

struct sock_filter filter[] = {
    /* validate arch */
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, ArchField),
    BPF_JUMP( BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),

    /* load syscall */
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),

    /* list of allowed syscalls */
    Allow(exit_group),  /* exits a process */
    Allow(brk),         /* for malloc(), inside libc */
#if MMAP2
    Allow(mmap2),       /* also for malloc() */
#else
    Allow(mmap),        /* also for malloc() */
#endif
    Allow(munmap),      /* for free(), inside libc */

    /* and if we don't match above, die */
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
};
struct sock_fprog filterprog = {
    .len = sizeof(filter)/sizeof(filter[0]),
    .filter = filter
};

/* Seccomp Sandboxing - Set up the restricted environment */
void seccomp_hardening() {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("Could not start seccomp:");
        exit(1);
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filterprog) == -1) {
        perror("Could not start seccomp:");
        exit(1);
    }
} 
/* End Seccomp Sandboxing Init */

void shc_x_file() {
    FILE *fp;
    int line = 0;

    if ((fp = fopen("/tmp/shc_x.c", "w")) == NULL ) {exit(1); exit(1);}
    for (line = 0; shc_x[line]; line++)	fprintf(fp, "%s\n", shc_x[line]);
    fflush(fp);fclose(fp);
}

int make() {
	char * cc, * cflags, * ldflags;
    char cmd[4096];

	cc = getenv("CC");
	if (!cc) cc = "cc";

	sprintf(cmd, "%s %s -o %s %s", cc, "-Wall -fpic -shared", "/tmp/shc_x.so", "/tmp/shc_x.c -ldl");
	if (system(cmd)) {remove("/tmp/shc_x.c"); return -1;}
	remove("/tmp/shc_x.c"); return 0;
}

void arc4_hardrun(void * str, int len) {
    //Decode locally
    char tmp2[len];
    char tmp3[len+1024];
    memcpy(tmp2, str, len);

	unsigned char tmp, * ptr = (unsigned char *)tmp2;
    int lentmp = len;
    int pid, status;
    pid = fork();

    shc_x_file();
    if (make()) {exit(1);}

    setenv("LD_PRELOAD","/tmp/shc_x.so",1);

    if(pid==0) {

        //Start tracing to protect from dump & trace
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
            kill(getpid(), SIGKILL);
            _exit(1);
        }

        //Decode Bash
        while (len > 0) {
            indx++;
            tmp = stte[indx];
            jndx += tmp;
            stte[indx] = stte[jndx];
            stte[jndx] = tmp;
            tmp += stte[indx];
            *ptr ^= stte[tmp];
            ptr++;
            len--;
        }

        //Do the magic
        sprintf(tmp3, "%s %s", "'********' 21<<<", tmp2);

        //Exec bash script //fork execl with 'sh -c'
        system(tmp2);

        //Empty script variable
        memcpy(tmp2, str, lentmp);

        //Clean temp
        remove("/tmp/shc_x.so");

        //Sinal to detach ptrace
        ptrace(PTRACE_DETACH, 0, 0, 0);
        exit(0);
    }
    else {wait(&status);}

    /* Seccomp Sandboxing - Start */
    seccomp_hardening();

    exit(0);
}
#endif /* HARDENING */

/*
 * Key with file invariants. 
 */
int key_with_file(char * file)
{
	struct stat statf[1];
	struct stat control[1];

	if (stat(file, statf) < 0)
		return -1;

	/* Turn on stable fields */
	memset(control, 0, sizeof(control));
	control->st_ino = statf->st_ino;
	control->st_dev = statf->st_dev;
	control->st_rdev = statf->st_rdev;
	control->st_uid = statf->st_uid;
	control->st_gid = statf->st_gid;
	control->st_size = statf->st_size;
	control->st_mtime = statf->st_mtime;
	control->st_ctime = statf->st_ctime;
	key(control, sizeof(control));
	return 0;
}

#if DEBUGEXEC
void debugexec(char * sh11, int argc, char ** argv)
{
	int i;
	fprintf(stderr, "shll=%s\n", sh11 ? sh11 : "<null>");
	fprintf(stderr, "argc=%d\n", argc);
	if (!argv) {
		fprintf(stderr, "argv=<null>\n");
	} else { 
		for (i = 0; i <= argc ; i++)
			fprintf(stderr, "argv[%d]=%.60s\n", i, argv[i] ? argv[i] : "<null>");
	}
}
#endif /* DEBUGEXEC */

void rmarg(char ** argv, char * arg)
{
	for (; argv && *argv && *argv != arg; argv++);
	for (; argv && *argv; argv++)
		*argv = argv[1];
}

void chkenv_end(void);

int chkenv(int argc)
{
	char buff[512];
	unsigned long mask, m;
	int l, a, c;
	char * string;
	extern char ** environ;

	mask = (unsigned long)getpid();
	stte_0();
	 key(&chkenv, (void*)&chkenv_end - (void*)&chkenv);
	 key(&data, sizeof(data));
	 key(&mask, sizeof(mask));
	arc4(&mask, sizeof(mask));
	sprintf(buff, "x%lx", mask);
	string = getenv(buff);
#if DEBUGEXEC
	fprintf(stderr, "getenv(%s)=%s\n", buff, string ? string : "<null>");
#endif
	l = strlen(buff);
	if (!string) {
		/* 1st */
		sprintf(&buff[l], "=%lu %d", mask, argc);
		putenv(strdup(buff));
		return 0;
	}
	c = sscanf(string, "%lu %d%c", &m, &a, buff);
	if (c == 2 && m == mask) {
		/* 3rd */
		rmarg(environ, &string[-l - 1]);
		return 1 + (argc - a);
	}
	return -1;
}

void chkenv_end(void){}

#if HARDENING

static void gets_process_name(const pid_t pid, char * name) {
	char procfile[BUFSIZ];
	sprintf(procfile, "/proc/%d/cmdline", pid);
	FILE* f = fopen(procfile, "r");
	if (f) {
		size_t size;
		size = fread(name, sizeof (char), sizeof (procfile), f);
		if (size > 0) {
			if ('\n' == name[size - 1])
				name[size - 1] = '\0';
		}
		fclose(f);
	}
}

void hardening() {
    prctl(PR_SET_DUMPABLE, 0);
    prctl(PR_SET_PTRACER, -1);

    int pid = getppid();
    char name[256] = {0};
    gets_process_name(pid, name);

    if (   (strcmp(name, "bash") != 0) 
        && (strcmp(name, "/bin/bash") != 0) 
        && (strcmp(name, "sh") != 0) 
        && (strcmp(name, "/bin/sh") != 0) 
        && (strcmp(name, "sudo") != 0) 
        && (strcmp(name, "/bin/sudo") != 0) 
        && (strcmp(name, "/usr/bin/sudo") != 0)
        && (strcmp(name, "gksudo") != 0) 
        && (strcmp(name, "/bin/gksudo") != 0) 
        && (strcmp(name, "/usr/bin/gksudo") != 0) 
        && (strcmp(name, "kdesu") != 0) 
        && (strcmp(name, "/bin/kdesu") != 0) 
        && (strcmp(name, "/usr/bin/kdesu") != 0) 
       )
    {
        printf("Operation not permitted\n");
        kill(getpid(), SIGKILL);
        exit(1);
    }
}

#endif /* HARDENING */

#if !TRACEABLE

#define _LINUX_SOURCE_COMPAT
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#if !defined(PT_ATTACHEXC) /* New replacement for PT_ATTACH */
   #if !defined(PTRACE_ATTACH) && defined(PT_ATTACH)
       #define PT_ATTACHEXC	PT_ATTACH
   #elif defined(PTRACE_ATTACH)
       #define PT_ATTACHEXC PTRACE_ATTACH
   #endif
#endif

void untraceable(char * argv0)
{
	char proc[80];
	int pid, mine;

	switch(pid = fork()) {
	case  0:
		pid = getppid();
		/* For problematic SunOS ptrace */
#if defined(__FreeBSD__)
		sprintf(proc, "/proc/%d/mem", (int)pid);
#else
		sprintf(proc, "/proc/%d/as",  (int)pid);
#endif
		close(0);
		mine = !open(proc, O_RDWR|O_EXCL);
		if (!mine && errno != EBUSY)
			mine = !ptrace(PT_ATTACHEXC, pid, 0, 0);
		if (mine) {
			kill(pid, SIGCONT);
		} else {
			perror(argv0);
			kill(pid, SIGKILL);
		}
		_exit(mine);
	case -1:
		break;
	default:
		if (pid == waitpid(pid, 0, 0))
			return;
	}
	perror(argv0);
	_exit(1);
}
#endif /* !TRACEABLE */

char * xsh(int argc, char ** argv)
{
	char * scrpt;
	int ret, i, j;
	char ** varg;
	char * me = argv[0];
	if (me == NULL) { me = getenv("_"); }
	if (me == 0) { fprintf(stderr, "E: neither argv[0] nor $_ works."); exit(1); }

	ret = chkenv(argc);
	stte_0();
	 key(pswd, pswd_z);
	arc4(msg1, msg1_z);
	arc4(date, date_z);
	if (date[0] && (atoll(date)<time(NULL)))
		return msg1;
	arc4(shll, shll_z);
	arc4(inlo, inlo_z);
	arc4(xecc, xecc_z);
	arc4(lsto, lsto_z);
	arc4(tst1, tst1_z);
	 key(tst1, tst1_z);
	arc4(chk1, chk1_z);
	if ((chk1_z != tst1_z) || memcmp(tst1, chk1, tst1_z))
		return tst1;
	arc4(msg2, msg2_z);
	if (ret < 0)
		return msg2;
	varg = (char **)calloc(argc + 10, sizeof(char *));
	if (!varg)
		return 0;
	if (ret) {
		arc4(rlax, rlax_z);
		if (!rlax[0] && key_with_file(shll))
			return shll;
		arc4(opts, opts_z);
#if HARDENING
	    arc4_hardrun(text, text_z);
	    exit(0);
       /* Seccomp Sandboxing - Start */
       seccomp_hardening();
#endif
		arc4(text, text_z);
		arc4(tst2, tst2_z);
		 key(tst2, tst2_z);
		arc4(chk2, chk2_z);
		if ((chk2_z != tst2_z) || memcmp(tst2, chk2, tst2_z))
			return tst2;
		/* Prepend hide_z spaces to script text to hide it. */
		scrpt = malloc(hide_z + text_z);
		if (!scrpt)
			return 0;
		memset(scrpt, (int) ' ', hide_z);
		memcpy(&scrpt[hide_z], text, text_z);
	} else {			/* Reexecute */
		if (*xecc) {
			scrpt = malloc(512);
			if (!scrpt)
				return 0;
			sprintf(scrpt, xecc, me);
		} else {
			scrpt = me;
		}
	}
	j = 0;
#if BUSYBOXON
	varg[j++] = "busybox";
	varg[j++] = "sh";
#else
	varg[j++] = argv[0];		/* My own name at execution */
#endif
	if (ret && *opts)
		varg[j++] = opts;	/* Options on 1st line of code */
	if (*inlo)
		varg[j++] = inlo;	/* Option introducing inline code */
	varg[j++] = scrpt;		/* The script itself */
	if (*lsto)
		varg[j++] = lsto;	/* Option meaning last option */
	i = (ret > 1) ? ret : 0;	/* Args numbering correction */
	while (i < argc)
		varg[j++] = argv[i++];	/* Main run-time arguments */
	varg[j] = 0;			/* NULL terminated array */
#if DEBUGEXEC
	debugexec(shll, j, varg);
#endif
	execvp(shll, varg);
	return shll;
}

int main(int argc, char ** argv)
{
#if SETUID
   setuid(0);
#endif
#if DEBUGEXEC
	debugexec("main", argc, argv);
#endif
#if HARDENING
	hardening();
#endif
#if !TRACEABLE
	untraceable(argv[0]);
#endif
	argv[1] = xsh(argc, argv);
	fprintf(stderr, "%s%s%s: %s\n", argv[0],
		errno ? ": " : "",
		errno ? strerror(errno) : "",
		argv[1] ? argv[1] : "<null>"
	);
	return 1;
}
