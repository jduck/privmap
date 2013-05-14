/*
 * show the privileges of running processes
 *
 * Joshua J. Drake <jduck>
 */
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>


/*
 * NOTE: the format strings used here are from fs/proc/array.c in 
 * the Linux kernel source.
 */
#define UID_FMT "Uid:\t%d\t%d\t%d\t%d\n"
#define GID_FMT "Gid:\t%d\t%d\t%d\t%d\n"


typedef struct stru_uids {
    uid_t real, effective, saved, fs;
} uids_t;

typedef struct stru_gids {
    gid_t real, effective, saved, fs;
} gids_t;

typedef struct stru_process {
    pid_t pid;
    char cmdline[8192];
    struct stru_uids uid;
    struct stru_gids gid;
    int ngroups;
    gid_t groups[NGROUPS_MAX];
    struct stru_process *next;
} process_t;

process_t *head = NULL;
process_t *tail = NULL;


/* for searching output */
pid_t search_pid = -1;
uid_t search_uid = -1;
gid_t search_gid = -1;
char *search_cmd = NULL;


void perror_str(const char *fmt, ...);
char *my_stpcpy(char *dst, const char *src);
int get_process_info(process_t *pp, const char *pidstr);
void show_process_info(process_t *pp);
int get_privileges(process_t *pp, const char *pidstr);
char *get_user_name(uid_t uid);
char *get_group_name(gid_t gid);
FILE *open_proc_entry(pid_t pid, const char *pidstr, const char *entry);
void add_process(process_t *pp);
int process_matches(process_t *pp);
void usage(char *argv[]);


int
main(int argc, char *argv[])
{
    DIR *pd;
    struct dirent *pe;
    process_t *pp;
    int c;

    if (!(pd = opendir("/proc"))) {
        perror_str("[!] Unable to open /proc");
        return 1;
    }

    /* process args */
    while ((c = getopt(argc, argv, "g:p:u:")) != -1) {
        char *end = NULL;
        int num;

        switch(c) {
            case 'g':
                num = strtol(optarg, &end, 0);
                if (!end || *end) {
                    /* try to resolve the name */
                    struct group *pg = getgrnam(optarg);

                    if (!pg) {
                        fprintf(stderr, "[!] Unknown group name: \"%s\"\n", optarg);
                        return 1;
                    }
                    search_gid = pg->gr_gid;
                }
                else
                    search_gid = num;
                break;

            case 'p':
                num = strtol(optarg, &end, 0);
                if (!end || *end) {
                    search_cmd = optarg;
                }
                else
                    search_pid = num;
                break;

            case 'u':
                num = strtol(optarg, &end, 0);
                if (!end || *end) {
                    /* try to resolve the name */
                    struct passwd *pw = getpwnam(optarg);

                    if (!pw) {
                        fprintf(stderr, "[!] Unknown user name: \"%s\"\n", optarg);
                        return 1;
                    }
                    search_uid = pw->pw_uid;
                }
                else
                    search_uid = num;
                break;

            default:
                usage(argv);
                return 1;
                /* not reached */
        }
    }

    /* first, scan the system to get all the processes and their privileges */
    while ((pe = readdir(pd))) {
        process_t p;

        memset(&p, 0, sizeof(p));

        /* we only care about numeric only directories (pid dirs) */
        if (strtok(pe->d_name, "0123456789"))
            continue;

#ifdef DEBUG
        printf("[*] checking: 0x%x 0x%x 0x%x 0x%x %s ...\n", 
               (unsigned int)pe->d_ino, (unsigned int)pe->d_off,
               pe->d_reclen,
               pe->d_type, pe->d_name);
#endif
        p.pid = atoi(pe->d_name);
        if (get_process_info(&p, pe->d_name)) {
            /* add it to the list */
            add_process(&p);
        }
    }

    /* show the processes info */
    for (pp = head; pp; pp = pp->next) {
        if (process_matches(pp))
            show_process_info(pp);
    }

    closedir(pd);
    return 0;
}


void
perror_str(const char *fmt, ...)
{
    char *ptr = NULL;
    va_list vl;

    va_start(vl, fmt);
    if (vasprintf(&ptr, fmt, vl) == -1) {
        perror(fmt);
        return;
    }
    perror(ptr);
    free(ptr);
}

char *my_stpcpy(char *dst, const char *src)
{
    char *q = dst;
    const char *p = src;

    while (*p)
        *q++ = *p++;
    return q;
}


FILE *
open_proc_entry(pid_t pid, const char *pidstr, const char *entry)
{
    char canonical_path[PATH_MAX+1] = { 0 };
    char *end;
    size_t entry_len = strlen(entry);

    if (strlen("/proc/") + strlen(pidstr) + 1 + entry_len + 1 >= PATH_MAX) {
        fprintf(stderr, "[!] name too long \"/proc/%s/%s\"\n", pidstr, entry);
        return NULL;
    }

    end = my_stpcpy(canonical_path, "/proc/");
    end = my_stpcpy(end, pidstr);
    *end++ = '/';
    strcpy(end, entry);

    return fopen(canonical_path, "r");
}


char *
get_user_name(uid_t uid)
{
    struct passwd *pw = getpwuid(uid);

    if (!pw)
        return "?";
    return pw->pw_name;
}

char *
get_group_name(gid_t gid)
{
    struct group *pg = getgrgid(gid);

    if (!pg)
        return "?";
    return pg->gr_name;
}


int
get_process_info(process_t *pp, const char *pidstr)
{
    FILE *fp;
    size_t len;

    /* first, extract the cmdline, if possible. */
    fp = open_proc_entry(pp->pid, pidstr, "cmdline");
    if (fp) {
        len = fread(pp->cmdline, 1, sizeof(pp->cmdline) - 1, fp);
        if (len > 0) {
            size_t i;

            for (i = 0; i < len; i++) {
                if (pp->cmdline[i] == '\0')
                    pp->cmdline[i] = ' ';
            }
        }
        fclose(fp);
    }

    /* processes without a cmdline are probably kernel process..
     * their user/groups will always be root
     */
    if (!pp->cmdline[0])
        return 0;

#if 0
    fp = NULL;
    if (!cmdline[0])
        fp = open_proc_entry(pp->pid, pidstr, "comm");
    if (fp) {
        len = fread(pp->cmdline, 1, sizeof(pp->cmdline), fp);
        if (len > 0) {
            if (pp->cmdline[len - 1] == '\n')
                pp->cmdline[len - 1] = '\0';
        }
        fclose(fp);
    }
#endif

    return get_privileges(pp, pidstr);
}

void
show_process_info(process_t *pp)
{
    int i;

    printf("[*] pid: %d, cmd: %s\n", pp->pid, pp->cmdline);

    /* show the privileges */
    printf("%11s: %d(%s), %d(%s), %d(%s), %d(%s)\n", "uid",
        pp->uid.real, get_user_name(pp->uid.real),
        pp->uid.effective, get_user_name(pp->uid.effective),
        pp->uid.saved, get_user_name(pp->uid.saved),
        pp->uid.fs, get_user_name(pp->uid.fs));
    printf("%11s: %d(%s), %d(%s), %d(%s), %d(%s)\n", "gid",
        pp->gid.real, get_group_name(pp->gid.real),
        pp->gid.effective, get_group_name(pp->gid.effective),
        pp->gid.saved, get_group_name(pp->gid.saved),
        pp->gid.fs, get_group_name(pp->gid.fs));

    if (pp->ngroups > 0) {
        printf("%11s: ", "groups");
        for (i = 0; i < pp->ngroups; i++) {
            printf("%d(%s)", pp->groups[i], get_group_name(pp->groups[i]));
            if (i != pp->ngroups - 1)
                printf(", ");
        }
        printf("\n");
    }
    printf("\n");
}

        
int
get_privileges(process_t *pp, const char *pidstr)
{
    char buf[1024] = { 0 };
    FILE *fp = open_proc_entry(pp->pid, pidstr, "status");

    if (!fp) {
        fprintf(stderr, "[!] Unable to open status for pid: %s\n", pidstr);
        return 0;
    }

    /* parse the status file */
    while (fgets(buf, sizeof(buf) - 1, fp)) {
        if (strncmp(buf, "Uid:\t", 5) == 0) {
            uids_t u;

            if (sscanf(buf, UID_FMT, &u.real, &u.effective, &u.saved, &u.fs) == 4) {
                pp->uid = u;
            }
        }
        else if (strncmp(buf, "Gid:\t", 5) == 0) {
            gids_t g;

            if (sscanf(buf, GID_FMT, &g.real, &g.effective, &g.saved, &g.fs) == 4) {
                pp->gid = g;
            }
        }
        else if (strncmp(buf, "Groups:\t", 8) == 0) {
            char *p = buf + 8;
            char *tok;

            /* don't show the groups line for proceses with no supplementary 
             * groups */
            if (!*p || *p == '\n')
                continue;

            /* show supplementary groups */
            tok = strtok(p, " \t");
            while (tok && tok[0] >= '0' && tok[0] <= '9') {
                gid_t gid = atoi(tok);

                if (pp->ngroups >= NGROUPS_MAX) {
                    fprintf(stderr, "[!] Too many groups for pid: %s\n", pidstr);
                    return 0;
                }

                pp->groups[pp->ngroups++] = gid;

                //printf("--- TOK: %s\n", tok);
                tok = strtok(NULL, " \t");
            }
        }
    }

    fclose(fp);
    return 1;
}


void
add_process(process_t *pp)
{
    process_t *np;

    np = (process_t *)malloc(sizeof(process_t));
    if (!np) {
        fprintf(stderr, "[!] Out of memory adding a process!\n");
        exit(1);
    }
    memcpy(np, pp, sizeof(process_t));
    if (!head)
        head = np;
    if (tail)
        tail->next = np;
    tail = np;
}


int process_matches(process_t *pp)
{
    /* no search == show everything */
    if (search_pid == -1 && search_uid == -1 && search_gid == -1 && !search_cmd)
        return 1;

    /* pid search - does it match? */
    if (search_pid != -1 && pp->pid == search_pid)
        return 1;

    /* uid search - does it match? */
    if (search_uid != -1 && 
            (pp->uid.real == search_uid
             || pp->uid.effective == search_uid
             || pp->uid.saved == search_uid
             || pp->uid.fs == search_uid))
        return 1;

    /* gid search - does it match? */
    if (search_gid != -1) {
        int i;

        if (pp->gid.real == search_gid
             || pp->gid.effective == search_gid
             || pp->gid.saved == search_gid
             || pp->gid.fs == search_gid)
            return 1;

        /* check supplementary groups */
        for (i = 0; i < pp->ngroups; i++) {
            if (pp->groups[i] == search_gid)
                return 1;
        }
    }

    /* search by cmd substr */
    if (search_cmd && strstr(pp->cmdline, search_cmd))
        return 1;

    return 0;
}


void
usage(char *argv[])
{
    char *cmd = "privmap";

    if (argv && argv[0])
        cmd = argv[0];
    fprintf(stderr,
        "usage: %s [opts]\n"
        "\n"
        "supported options:\n"
        "-g <gid> \tshow only processes with the specified group id or name\n"
        "-p <pid> \tshow only processes with the specified process id or name\n"
        "-u <uid> \tshow only processes with the specified user id or name\n"
        , cmd);
}
