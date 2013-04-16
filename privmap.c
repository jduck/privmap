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


void perror_str(const char *fmt, ...);
char *my_stpcpy(char *dst, const char *src);
int show_process_info(pid_t pid, const char *pidstr);
void show_privileges(pid_t pid, const char *pidstr);
char *get_user_name(uid_t uid);
char *get_group_name(gid_t gid);
FILE *open_proc_entry(pid_t pid, const char *pidstr, const char *entry);


int
main(int c, char *v[])
{
    DIR *pd;
    struct dirent *pe;

    if (!(pd = opendir("/proc"))) {
        perror_str("[!] Unable to open /proc");
        return;
    }

    while ((pe = readdir(pd))) {
        pid_t pid;

        /* we only care about numeric only directories (pid dirs) */
        if (strtok(pe->d_name, "0123456789"))
            continue;

#ifdef DEBUG
        printf("[*] checking: 0x%x 0x%x 0x%x 0x%x %s ...\n", 
               (unsigned int)pe->d_ino, (unsigned int)pe->d_off,
               pe->d_reclen,
               pe->d_type, pe->d_name);
#endif
        pid = atoi(pe->d_name);
        if (show_process_info(pid, pe->d_name)) {
            show_privileges(pid, pe->d_name);
            printf("\n");
        }
    }

    closedir(pd);
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
    FILE *fp;
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
show_process_info(pid_t pid, const char *pidstr)
{
    FILE *fp;
    char cmdline[8192] = { 0 };
    size_t len;

    /* first, extract the cmdline, if possible. */
    fp = open_proc_entry(pid, pidstr, "cmdline");
    if (fp) {
        len = fread(cmdline, 1, sizeof(cmdline) - 1, fp);
        if (len > 0) {
            size_t i;

            for (i = 0; i < len; i++) {
                if (cmdline[i] == '\0')
                    cmdline[i] = ' ';
            }
        }
        fclose(fp);
    }

    /* processes without a cmdline are probably kernel process..
     * their user/groups will always be root
     */
    if (!cmdline[0])
        return 0;
#if 0
    fp = NULL;
    if (!cmdline[0])
        fp = open_proc_entry(pid, pidstr, "comm");
    if (fp) {
        len = fread(cmdline, 1, sizeof(cmdline), fp);
        if (len > 0) {
            if (cmdline[len - 1] == '\n')
                cmdline[len - 1] = '\0';
        }
        fclose(fp);
    }
#endif

    printf("[*] pid: %d, cmd: %s\n", pid, cmdline);
    return 1;
}


void
show_privileges(pid_t pid, const char *pidstr)
{
    char buf[1024] = { 0 };
    FILE *fp = open_proc_entry(pid, pidstr, "status");

    if (!fp) {
        fprintf(stderr, "[!] Unable to open status for pid: %s\n", pidstr);
        return;
    }

    /* parse the status file */
    while (fgets(buf, sizeof(buf) - 1, fp)) {
        if (strncmp(buf, "Uid:\t", 5) == 0) {
            uids_t u;

            if (sscanf(buf, UID_FMT, &u.real, &u.effective, &u.saved, &u.fs) == 4) {
                printf("%11s: %d(%s), %d(%s), %d(%s), %d(%s)\n", "uid",
                    u.real, get_user_name(u.real),
                    u.effective, get_user_name(u.effective),
                    u.saved, get_user_name(u.saved),
                    u.fs, get_user_name(u.fs));
            }
        }
        else if (strncmp(buf, "Gid:\t", 5) == 0) {
            gids_t g;

            if (sscanf(buf, GID_FMT, &g.real, &g.effective, &g.saved, &g.fs) == 4) {
                printf("%11s: %d(%s), %d(%s), %d(%s), %d(%s)\n", "gid",
                    g.real, get_group_name(g.real),
                    g.effective, get_group_name(g.effective),
                    g.saved, get_group_name(g.saved),
                    g.fs, get_group_name(g.fs));
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
            printf("%11s: ", "groups");
            tok = strtok(p, " \t");
            while (tok && tok[0] >= '0' && tok[0] <= '9') {
                gid_t gid = atoi(tok);

                //printf("--- TOK: %s\n", tok);
                printf("%d(%s)", gid, get_group_name(gid));
                tok = strtok(NULL, " \t");
                if (tok && tok[0] >= '0' && tok[0] <= '9')
                    printf(", ");
            }
            printf("\n");
        }
    }

    fclose(fp);
}
