/*
* interpret.c - Lookup values to something more readable
* Copyright (c) 2007 Red Hat Inc., Durham, North Carolina.
* All Rights Reserved. 
*
* This software may be freely redistributed and/or modified under the
* terms of the GNU General Public License as published by the Free
* Software Foundation; either version 2, or (at your option) any
* later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; see the file COPYING. If not, write to the
* Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*
* Authors:
*   Steve Grubb <sgrubb@redhat.com>
*/

#include "config.h"
#include "nvlist.h"
#include "nvpair.h"
#include "libaudit.h"
#include "internal.h"
#include "interpret.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <linux/net.h>
#include <netdb.h>
#include <sys/un.h>
#include <linux/ax25.h>
#include <linux/atm.h>
#include <linux/x25.h>
#include <linux/if.h>   // FIXME: remove when ipx.h is fixed
#include <linux/ipx.h>


typedef enum { AVC_UNSET, AVC_DENIED, AVC_GRANTED } avc_t;
typedef enum { S_UNSET=-1, S_FAILED, S_SUCCESS } success_t;

/* This is the list of field types that we can interpret */
enum { T_UID, T_GID, T_SYSCALL, T_ARCH, T_EXIT, T_ESCAPED, T_PERM, T_MODE,
T_SOCKADDR, T_FLAGS, T_PROMISC, T_CAPABILITY, T_SUCCESS, T_A0, T_A1, T_A2,
T_SIGNAL };

struct transtab {
    int   value;
    int   offset;
};

#define MSGSTRFIELD(line) MSGSTRFIELD1(line)
#define MSGSTRFIELD1(line) str##line

struct int_transtab {
    int        key;
    unsigned int  lvalue;
};

/* To create the following tables in a DSO-friendly way we split them in
 * two separate variables: a long string which is created by concatenating
 * all strings referenced in the table and the table itself, which uses
 * offsets instead of string pointers.  To do this without increasing
 * the maintenance burden we use a lot of preprocessor magic.  All the
 * maintainer has to do is to add a new entry to the included file and
 * recompile.  */


/*
 * This function will take a pointer to a 2 byte Ascii character buffer and
 * return the actual hex value.
 */
static unsigned char x2c(unsigned char *buf)
{
        static const char AsciiArray[17] = "0123456789ABCDEF";
        char *ptr;
        unsigned char total=0;

        ptr = strchr(AsciiArray, (char)toupper(buf[0]));
        if (ptr)
                total = (unsigned char)(((ptr-AsciiArray) & 0x0F)<<4);
        ptr = strchr(AsciiArray, (char)toupper(buf[1]));
        if (ptr)
                total += (unsigned char)((ptr-AsciiArray) & 0x0F);

        return total;
}

/* returns a freshly malloc'ed and converted buffer */
static const char *unescape(char *buf)
{
        int len, i;
        char saved, *str, *ptr = buf;

        /* Find the end of the name */
        if (*ptr == '(') {
                ptr = strchr(ptr, ')');
                if (ptr == NULL)
                        return NULL;
                else
                        ptr++;
        } else {
                while (isxdigit(*ptr))
                        ptr++;
        }
        saved = *ptr;
        *ptr = 0;
        str = strdup(buf);
        *ptr = saved;

        if (*buf == '(')
                return str;

        /* We can get away with this since the buffer is 2 times
         * bigger than what we are putting there.
         */
        len = strlen(str);
        if (len < 2) {
                free(str);
                return NULL;
        }
        ptr = str;
        for (i=0; i<len; i+=2) {
                *ptr = x2c((unsigned char *)&str[i]);
                ptr++;
        }
        *ptr = 0;
        return str;
}

static const char *success[3]= { "unset", "no", "yes" };
static const char *aulookup_success(int s)
{
	switch (s)
	{
		default:
			return success[0];
			break;
		case S_FAILED:
			return success[1];
			break;
		case S_SUCCESS:
			return success[2];
			break;
	}
}

static const union socktab_msgstr_t {
	struct {
#define _S(n, s) char MSGSTRFIELD(__LINE__)[sizeof (s)];
#include "socktab.h"
#undef _S
	};
	char str[0];
} socktab_msgstr = { {
#define _S(n, s) s,
#include "socktab.h"
#undef _S
} };
static const struct transtab socktab[] = {
#define _S(n, s) { n, offsetof(union socktab_msgstr_t,  \
				MSGSTRFIELD(__LINE__)) },
#include "socktab.h"
#undef _S
};
#define SOCK_NAMES (sizeof(socktab)/sizeof(socktab[0]))

static const char *aulookup_socketcall(long sc)
{
        int i;

        for (i = 0; i < SOCK_NAMES; i++)
                if (socktab[i].value == sc)
                        return socktab_msgstr.str + socktab[i].offset;

        return NULL;
}

/* This is from asm/ipc.h. Copying it for now as some platforms
 * have broken headers. */
#define SEMOP            1
#define SEMGET           2
#define SEMCTL           3
#define MSGSND          11
#define MSGRCV          12
#define MSGGET          13
#define MSGCTL          14
#define SHMAT           21
#define SHMDT           22
#define SHMGET          23
#define SHMCTL          24

/*
 * This table maps ipc calls to their text name
 */

static const union ipctab_msgstr_t {
        struct {
#define _S(n, s) char MSGSTRFIELD(__LINE__)[sizeof (s)];
#include "ipctab.h"
#undef _S
        };
        char str[0];
} ipctab_msgstr = { {
#define _S(n, s) s,
#include "ipctab.h"
#undef _S
} };
static const struct transtab ipctab[] = {
#define _S(n, s) { n, offsetof(union ipctab_msgstr_t,  \
                                MSGSTRFIELD(__LINE__)) },
#include "ipctab.h"
#undef _S
};
#define IPC_NAMES (sizeof(ipctab)/sizeof(ipctab[0]))

static const char *aulookup_ipccall(long ic)
{
        int i;

        for (i = 0; i < IPC_NAMES; i++)
                if (ipctab[i].value == ic)
                        return ipctab_msgstr.str + ipctab[i].offset;

        return NULL;
}

static nvpair uid_nvl;
static int uid_list_created=0;
static const char *aulookup_uid(uid_t uid, char *buf, size_t size)
{
	char *name = NULL;
	int rc;

	if (uid == -1) {
		snprintf(buf, size, "unset");
		return buf;
	}

	// Check the cache first
	if (uid_list_created == 0) {
		nvpair_create(&uid_nvl);
		nvpair_clear(&uid_nvl);
		uid_list_created = 1;
	}
	rc = nvpair_find_val(&uid_nvl, uid);
	if (rc) {
		name = uid_nvl.cur->name;
	} else {
		// Add it to cache
		struct passwd *pw;
		pw = getpwuid(uid);
		if (pw) {
			nvpnode nv;
			nv.name = strdup(pw->pw_name);
			nv.val = uid;
			nvpair_append(&uid_nvl, &nv);
			name = uid_nvl.cur->name;
		}
	}
	if (name != NULL)
		snprintf(buf, size, "%s", name);
	else
		snprintf(buf, size, "unknown(%d)", uid);
	return buf;
}

void aulookup_destroy_uid_list(void)
{
	if (uid_list_created == 0)
		return;

	nvpair_clear(&uid_nvl); 
	uid_list_created = 0;
}
hidden_def(aulookup_destroy_uid_list);

static nvpair gid_nvl;
static int gid_list_created=0;
static const char *aulookup_gid(gid_t gid, char *buf, size_t size)
{
	char *name = NULL;
	int rc;

	if (gid == -1) {
		snprintf(buf, size, "unset");
		return buf;
	}

	// Check the cache first
	if (gid_list_created == 0) {
		nvpair_create(&gid_nvl);
		nvpair_clear(&gid_nvl);
		gid_list_created = 1;
	}
	rc = nvpair_find_val(&gid_nvl, gid);
	if (rc) {
		name = gid_nvl.cur->name;
	} else {
		// Add it to cache
		struct group *gr;
		gr = getgrgid(gid);
		if (gr) {
			nvpnode nv;
			nv.name = strdup(gr->gr_name);
			nv.val = gid;
			nvpair_append(&gid_nvl, &nv);
			name = gid_nvl.cur->name;
		}
	}
	if (name != NULL)
		snprintf(buf, size, "%s", name);
	else
		snprintf(buf, size, "unknown(%d)", gid);
	return buf;
}

void aulookup_destroy_gid_list(void)
{
	if (gid_list_created == 0)
		return;

	nvpair_clear(&gid_nvl); 
	gid_list_created = 0;
}
hidden_def(aulookup_destroy_gid_list);

static const char *print_uid(const char *val)
{
        int uid;
        char name[64];

        errno = 0;
        uid = strtoul(val, NULL, 10);
        if (errno) {
		char *out;
                asprintf(&out, "conversion error(%s)", val);
                return out;
        }

        return strdup(aulookup_uid(uid, name, sizeof(name)));
}

static const char *print_gid(const char *val)
{
        int gid;
        char name[64];

        errno = 0;
        gid = strtoul(val, NULL, 10);
        if (errno) {
		char *out;
                asprintf(&out, "conversion error(%s)", val);
                return out;
        }

        return strdup(aulookup_gid(gid, name, sizeof(name)));
}

static const char *print_arch(const char *val, int machine)
{
        const char *ptr;
	char *out;

        if (machine < 0) {
                asprintf(&out, "unknown elf type(%s)", val);
                return out;
        }
        ptr = audit_machine_to_name(machine);
	if (ptr)
	        return strdup(ptr);
	else {
                asprintf(&out, "unknown machine type(%d)", machine);
                return out;
	}
}

static const char *print_syscall(const char *val, const rnode *r)
{
        const char *sys;
	char *out;
	int machine = r->machine, syscall = r->syscall;
	unsigned long long a0 = r->a0;

        if (machine < 0)
                machine = audit_detect_machine();
        if (machine < 0) {
                out = strdup(val);
                return out;
        }
        sys = audit_syscall_to_name(syscall, machine);
        if (sys) {
                const char *func = NULL;
                if (strcmp(sys, "socketcall") == 0)
                        func = aulookup_socketcall((long)a0);
                else if (strcmp(sys, "ipc") == 0)
                        func = aulookup_ipccall((long)a0);
                if (func)
                        asprintf(&out, "%s(%s)", sys, func);
                else
                        return strdup(sys);
        }
        else
                asprintf(&out, "unknown syscall(%d)", syscall);

	return out;
}

static const char *print_exit(const char *val)
{
        int ival;
	char *out;

        errno = 0;
        ival = strtol(val, NULL, 10);
        if (errno) {
                asprintf(&out, "conversion error(%s)", val);
                return out;
        }

        if (ival < 0) {
                asprintf(&out, "%d(%s)", ival, strerror(-ival));
		return out;
        }
        return strdup(val);

}

static const char *print_escaped(const char *val)
{
        if (*val == '"') {
                char *term, *out;
                val++;
                term = strchr(val, '"');
                if (term == NULL)
                        return strdup(" ");
                *term = 0;
                out = strdup(val);
		*term = '"';
		return out;
// FIXME: working here...was trying to detect (null) and handle that differently// The other 2 should have " around the file names.
/*      } else if (*val == '(') {
                char *term;
                val++;
                term = strchr(val, ' ');
                if (term == NULL)
                        return;
                *term = 0;
                printf("%s ", val); */
        } else {
                return unescape((char *)val);
        }
}

static const char *print_perm(const char *val)
{
        int ival, printed=0;
	char buf[32];

        errno = 0;
        ival = strtol(val, NULL, 10);
        if (errno) {
		char *out;
                asprintf(&out, "conversion error(%s)", val);
                return out;
        }

	buf[0] = 0;

        /* The kernel treats nothing as everything */
        if (ival == 0)
                ival = 0x0F;
        if (ival & AUDIT_PERM_READ) {
                strcat(buf, "read");
                printed = 1;
        }
        if (ival & AUDIT_PERM_WRITE) {
                if (printed)
                        strcat(buf, ",write");
                else
                        strcat(buf, "write");
                printed = 1;
        }
        if (ival & AUDIT_PERM_EXEC) {
                if (printed)
                        strcat(buf, ",exec");
                else
                        strcat(buf, "exec");
                printed = 1;
        }
        if (ival & AUDIT_PERM_ATTR) {
                if (printed)
                        strcat(buf, ",attr");
                else
                        strcat(buf, "attr");
        }
	return strdup(buf);
}

static const char *print_mode(const char *val)
{
        unsigned int ival;
	char *out, buf[48];

        errno = 0;
        ival = strtoul(val, NULL, 8);
        if (errno) {
                asprintf(&out, "conversion error(%s)", val);
                return out;
        }

	buf[0] = 0;

        // detect its type
        if (S_ISREG(ival))
                strcat(buf, "file,");
        else if (S_ISSOCK(ival))
                strcat(buf, "socket,");
        else if (S_ISDIR(ival))
                strcat(buf, "dir,");
        else if (S_ISLNK(ival))
                strcat(buf, "symlink,");
        else if (S_ISCHR(ival))
                strcat(buf, "char,");
        else if (S_ISBLK(ival))
                strcat(buf, "block,");
        else if (S_ISFIFO(ival))
                strcat(buf, "fifo,");

        // check on special bits
        if (S_ISUID & ival)
                strcat(buf, "suid,");
        if (S_ISGID & ival)
                strcat(buf, "sgid,");
        if (S_ISVTX & ival)
                strcat(buf, "sticky,");

	// and the read, write, execute flags in octal
        asprintf(&out, "%s %03o",  buf, (S_IRWXU|S_IRWXG|S_IRWXO) & ival);
	return out;
}

/*
 * This table maps socket families to their text name
 */
static const union famtab_msgstr_t {
        struct {
#define _S(n, s) char MSGSTRFIELD(__LINE__)[sizeof (s)];
#include "famtab.h"
#undef _S
        };
        char str[0];
} famtab_msgstr = { {
#define _S(n, s) s,
#include "famtab.h"
#undef _S
} };
static const struct transtab famtab[] = {
#define _S(n, s) { n, offsetof(union famtab_msgstr_t,  \
                                MSGSTRFIELD(__LINE__)) },
#include "famtab.h"
#undef _S
};
#define FAM_NAMES (sizeof(famtab)/sizeof(famtab[0]))

static const char *audit_lookup_fam(int fam)
{
        int i;

        for (i = 0; i < FAM_NAMES; i++)
                if (famtab[i].value == fam)
                        return famtab_msgstr.str + famtab[i].offset;

        return NULL;
}

static const char *print_sockaddr(const char *val)
{
        int slen;
        const struct sockaddr *saddr;
        char name[NI_MAXHOST], serv[NI_MAXSERV];
        const char *host;
        char *out;
        const char *str;

        slen = strlen(val)/2;
        host = unescape((char *)val);
        saddr = (struct sockaddr *)host;


        str = audit_lookup_fam(saddr->sa_family);
        if (str == NULL) {
                asprintf(&out, "unknown family(%d)", saddr->sa_family);
		return out;
	}

	// Now print address for some families
        switch (saddr->sa_family) {
                case AF_LOCAL:
                        {
                                const struct sockaddr_un *un =
                                        (struct sockaddr_un *)saddr;
                                if (un->sun_path[0])
                                        asprintf(&out, "%s %s", str,
							un->sun_path);
                                else // abstract name
                                        asprintf(&out, "%s %.108s", str,
							&un->sun_path[1]);
                        }
                        break;
                case AF_INET:
                        if (slen < sizeof(struct sockaddr_in)) {
                                asprintf(&out, "%s sockaddr len too short",
						 str);
                                free((char *)host);
                                return out;
                        }
                        slen = sizeof(struct sockaddr_in);
                        if (getnameinfo(saddr, slen, name, NI_MAXHOST, serv,
                                NI_MAXSERV, NI_NUMERICHOST |
                                        NI_NUMERICSERV) == 0 ) {
                                asprintf(&out, "%s host:%s serv:%s", str,
						name, serv);
                        } else
                                asprintf(&out, "%s (error resolving addr)",
						 str);
                        break;
                case AF_AX25:
                        {
                                const struct sockaddr_ax25 *x =
                                                (struct sockaddr_ax25 *)saddr;
                                asprintf(&out, "%s call:%c%c%c%c%c%c%c", str,
                                        x->sax25_call.ax25_call[0],
                                        x->sax25_call.ax25_call[1],
                                        x->sax25_call.ax25_call[2],
                                        x->sax25_call.ax25_call[3],
                                        x->sax25_call.ax25_call[4],
                                        x->sax25_call.ax25_call[5],
                                        x->sax25_call.ax25_call[6]
                                );
                        }
                        break;
                case AF_IPX:
                        {
                                const struct sockaddr_ipx *ip =
                                                (struct sockaddr_ipx *)saddr;
                                asprintf(&out, "%s port:%d net:%u", str,
                                        ip->sipx_port, ip->sipx_network);
                        }
                        break;
                case AF_ATMPVC:
                        {
                                const struct sockaddr_atmpvc* at =
                                        (struct sockaddr_atmpvc *)saddr;
                                asprintf(&out, "%s int:%d", str, 
						at->sap_addr.itf);
                        }
                        break;
                case AF_X25:
                        {
                                const struct sockaddr_x25* x =
                                        (struct sockaddr_x25 *)saddr;
                                asprintf(&out, "%s addr:%.15s", str,
						x->sx25_addr.x25_addr);
                        }
                        break;
                case AF_INET6:
                        if (slen < sizeof(struct sockaddr_in6)) {
                                asprintf(&out, "%s sockaddr6 len too short", 
						str);
                                free((char *)host);
                                return out;
                        }
                        slen = sizeof(struct sockaddr_in6);
                        if (getnameinfo(saddr, slen, name, NI_MAXHOST, serv,
                                NI_MAXSERV, NI_NUMERICHOST |
                                        NI_NUMERICSERV) == 0 ) {
                                asprintf(&out, "%s host:%s serv:%s", str,
						name, serv);
                        } else
                                asprintf(&out, "%s (error resolving addr)",
						str);
                        break;
                case AF_NETLINK:
                        {
                                const struct sockaddr_nl *n =
                                                (struct sockaddr_nl *)saddr;
                                asprintf(&out, "%s pid:%u", str, n->nl_pid);
                        }
                        break;
        }
        free((char *)host);
	return out;
}

/*
 * This table maps file system flags to their text name
 */
static const union flagtab_msgstr_t {
        struct {
#define _S(n, s) char MSGSTRFIELD(__LINE__)[sizeof (s)];
#include "flagtab.h"
#undef _S
        };
        char str[0];
} flagtab_msgstr = { {
#define _S(n, s) s,
#include "flagtab.h"
#undef _S
} };
static const struct transtab flagtab[] = {
#define _S(n, s) { n, offsetof(union flagtab_msgstr_t,  \
                                MSGSTRFIELD(__LINE__)) },
#include "flagtab.h"
#undef _S
};
#define FLAG_NAMES (sizeof(flagtab)/sizeof(flagtab[0]))

static const char *print_flags(const char *val)
{
        int flags, i,cnt = 0;
	char *out, buf[80];

        errno = 0;
        flags = strtoul(val, NULL, 16);
        if (errno) {
                asprintf(&out, "conversion error(%s)", val);
                return out;
        }
        if (flags == 0) {
                asprintf(&out, "none");
                return out;
        }
	buf[0] = 0;
        for (i=0; i<FLAG_NAMES; i++) {
                if (flagtab[i].value & flags) {
                        if (!cnt) {
                                strcat(buf, 
					flagtab_msgstr.str + flagtab[i].offset);
                                cnt++;
                        } else {
                                strcat(buf, ",");
                                strcat(buf,
					flagtab_msgstr.str + flagtab[i].offset);
			}
                }
        }
	return strdup(buf);
}

static const char *print_promiscuous(const char *val)
{
        int ival;

        errno = 0;
        ival = strtol(val, NULL, 10);
        if (errno) {
		char *out;
                asprintf(&out, "conversion error(%s)", val);
                return out;
        }

        if (ival == 0)
                return strdup("no");
        else
                return strdup("yes");
}

/*
 * This table maps file system flags to their text name
 */
static const union captab_msgstr_t {
        struct {
#define _S(n, s) char MSGSTRFIELD(__LINE__)[sizeof (s)];
#include "captab.h"
#undef _S
        };
        char str[0];
} captab_msgstr = { {
#define _S(n, s) s,
#include "captab.h"
#undef _S
} };
static const struct transtab captab[] = {
#define _S(n, s) { n, offsetof(union captab_msgstr_t,  \
                                MSGSTRFIELD(__LINE__)) },
#include "captab.h"
#undef _S
};
#define CAP_NAMES (sizeof(captab)/sizeof(captab[0]))

static const char *print_capabilities(const char *val)
{
        int cap, i;
	char *out;

        errno = 0;
        cap = strtoul(val, NULL, 10);
        if (errno) {
                asprintf(&out, "conversion error(%s)", val);
                return out;
        }

        for (i = 0; i < CAP_NAMES; i++) {
                if (captab[i].value == cap) {
                        return strdup(captab_msgstr.str + captab[i].offset);
                }

        }
	asprintf(&out, "unknown capability(%s)", val);
	return out;
}

static const char *print_success(const char *val)
{
        int res;

	if (isdigit(*val)) {
	        errno = 0;
        	res = strtoul(val, NULL, 10);
	        if (errno) {
			char *out;
                	asprintf(&out, "conversion error(%s)", val);
	                return out;
        	}

	        return strdup(aulookup_success(res));
	} else
		return strdup(val);
}

/*
 * This table maps open syscall flags to their text name
 */
static const union openflagtab_msgstr_t {
        struct {
#define _S(n, s) char MSGSTRFIELD(__LINE__)[sizeof (s)];
#include "open-flagtab.h"
#undef _S
        };
        char str[0];
} openflagtab_msgstr = { {
#define _S(n, s) s,
#include "open-flagtab.h"
#undef _S
} };
static const struct transtab openflagtab[] = {
#define _S(n, s) { n, offsetof(union openflagtab_msgstr_t,  \
                                MSGSTRFIELD(__LINE__)) },
#include "open-flagtab.h"
#undef _S
};
#define OPEN_FLAG_NAMES (sizeof(openflagtab)/sizeof(openflagtab[0]))

static const char *print_open_flags(int flags)
{
        int i, cnt = 0;
	char buf[144];

	buf[0] = 0;
        if ((flags & O_ACCMODE) == 0) {
		// Handle O_RDONLY specially
                strcat(buf, openflagtab_msgstr.str);
                cnt++;
        }
        for (i=0; i<OPEN_FLAG_NAMES; i++) {
                if (openflagtab[i].value & flags) {
                        if (!cnt) {
                                strcat(buf, 
				openflagtab_msgstr.str + openflagtab[i].offset);
                                cnt++;
                        } else {
                                strcat(buf, "|");
                                strcat(buf,
				openflagtab_msgstr.str + openflagtab[i].offset);
			}
                }
        }
	return strdup(buf);
}

/*
 * This table maps clone syscall flags to their text name
 */
static const union cloneflagtab_msgstr_t {
        struct {
#define _S(n, s) char MSGSTRFIELD(__LINE__)[sizeof (s)];
#include "clone-flagtab.h"
#undef _S
        };
        char str[0];
} cloneflagtab_msgstr = { {
#define _S(n, s) s,
#include "clone-flagtab.h"
#undef _S
} };
static const struct transtab cloneflagtab[] = {
#define _S(n, s) { n, offsetof(union cloneflagtab_msgstr_t,  \
                                MSGSTRFIELD(__LINE__)) },
#include "clone-flagtab.h"
#undef _S
};
#define CLONE_FLAG_NAMES (sizeof(cloneflagtab)/sizeof(cloneflagtab[0]))

static const char *print_clone_flags(int flags)
{
        int i, cnt = 0;
	char buf[192];

	buf[0] = 0;
        for (i=0; i<CLONE_FLAG_NAMES; i++) {
                if (cloneflagtab[i].value & flags) {
                        if (!cnt) {
                                strcat(buf, 
			cloneflagtab_msgstr.str + cloneflagtab[i].offset);
                                cnt++;
                        } else {
                                strcat(buf, "|");
                                strcat(buf,
			cloneflagtab_msgstr.str + cloneflagtab[i].offset);
			}
                }
        }
	if (buf[0] == 0)
		snprintf(buf, sizeof(buf), "%d", flags);
	return strdup(buf);
}

/*
 * This table maps fcntl syscall cmds to their text name
 */
static const union fcntltab_msgstr_t {
        struct {
#define _S(n, s) char MSGSTRFIELD(__LINE__)[sizeof (s)];
#include "fcntl-cmdtab.h"
#undef _S
        };
        char str[0];
} fcntltab_msgstr = { {
#define _S(n, s) s,
#include "fcntl-cmdtab.h"
#undef _S
} };
static const struct transtab fcntltab[] = {
#define _S(n, s) { n, offsetof(union fcntltab_msgstr_t,  \
                                MSGSTRFIELD(__LINE__)) },
#include "fcntl-cmdtab.h"
#undef _S
};
#define FCNTL_CMD_NAMES (sizeof(fcntltab)/sizeof(fcntltab[0]))

static const char *print_fcntl_cmd(int cmd)
{
        int i;
	char *out;

        for (i = 0; i < FCNTL_CMD_NAMES; i++) {
                if (fcntltab[i].value == cmd) {
                        return strdup(fcntltab_msgstr.str + fcntltab[i].offset);
                }

        }
	asprintf(&out, "unknown fcntl command(%d)", cmd);
	return out;
}

static const char *print_a0(const char *val, const rnode *r)
{
	int machine = r->machine, syscall = r->syscall;
	const char *sys = audit_syscall_to_name(syscall, machine);
	if (sys) {
		/* Unused right now... */
	}
	return strdup(val);
}

static const char *print_a1(const char *val, const rnode *r)
{
	int machine = r->machine, syscall = r->syscall;
	char *out;
	const char *sys = audit_syscall_to_name(syscall, machine);
	if (sys) {
		if (strcmp(sys, "open") == 0) {
			int ival;

			errno = 0;
			ival = strtoul(val, NULL, 16);
		        if (errno) {
                		asprintf(&out, "conversion error(%s)", val);
	                	return out;
	        	}
			return print_open_flags(ival);
		} else if (strncmp(sys, "fcntl", 5) == 0) {
			int ival;

			errno = 0;
			ival = strtoul(val, NULL, 16);
		        if (errno) {
                		asprintf(&out, "conversion error(%s)", val);
	                	return out;
	        	}
			return print_fcntl_cmd(ival);
		}
	}
	return strdup(val);
}

static const char *print_a2(const char *val, const rnode *r)
{
	int machine = r->machine, syscall = r->syscall;
	char *out;
	const char *sys = audit_syscall_to_name(syscall, machine);
	if (sys) {
		if (strcmp(sys, "clone") == 0) {
			int ival;

			errno = 0;
			ival = strtoul(val, NULL, 16);
		        if (errno) {
                		asprintf(&out, "conversion error(%s)", val);
	                	return out;
	        	}
			return print_clone_flags(ival);
		} else if (strncmp(sys, "fcntl", 5) == 0) {
			int ival;

			errno = 0;
			ival = strtoul(val, NULL, 16);
		        if (errno) {
                		asprintf(&out, "conversion error(%s)", val);
	                	return out;
	        	}
			switch (r->a1)
			{
				case F_SETOWN:
					return print_uid(val);
				case F_SETFL:
				case F_SETLEASE:
				case F_GETLEASE:
				case F_NOTIFY:
					break;
			}
		}
	}
	return strdup(val);
}

static const char *print_signals(const char *val)
{
	int i;
	char *out;

	errno = 0;
        i = strtoul(val, NULL, 10);
	if (errno) 
		asprintf(&out, "conversion error(%s)", val);
	else
		out = strdup(strsignal(i));
	return out;
}

/*
 * This table translates field names into a type that identifies the
 * interpreter to use on it.
 */

static const union typetab_msgstr_t {
        struct {
#define _S(n, s) char MSGSTRFIELD(__LINE__)[sizeof (s)];
#include "typetab.h"
#undef _S
        };
        char str[0];
} typetab_msgstr = { {
#define _S(n, s) s,
#include "typetab.h"
#undef _S
} };
static const struct transtab typetab[] = {
#define _S(n, s) { n, offsetof(union typetab_msgstr_t,  \
                                MSGSTRFIELD(__LINE__)) },
#include "typetab.h"
#undef _S
};
#define TYPE_NAMES (sizeof(typetab)/sizeof(typetab[0]))


static int audit_lookup_type(const char *name)
{
	int i;

	for (i = 0; i < TYPE_NAMES; i++)
		if (!strcmp(typetab_msgstr.str + typetab[i].offset, name))
			return typetab[i].value;
	return -1;
}

const char *interpret(const rnode *r)
{
	const nvlist *nv = &r->nv;
	int type, comma = 0;
	nvnode *n;
	const char *out;
	const char *name = nvlist_get_cur_name(nv);
	const char *val = nvlist_get_cur_val(nv);

	if (r->type == AUDIT_EXECVE && name[0] == 'a')
		type = T_ESCAPED;
	else
		type = audit_lookup_type(name);
	switch(type) {
		case T_UID:
			out = print_uid(val);
			break;
		case T_GID:
			out = print_gid(val);
			break;
		case T_SYSCALL:
			out = print_syscall(val, r);
			break;
		case T_ARCH:
			out = print_arch(val, r->machine);
			break;
		case T_EXIT:
			out = print_exit(val);
			break;
		case T_ESCAPED:
			out = print_escaped(val);
                        break;
		case T_PERM:
			out = print_perm(val);
			break;
		case T_MODE:
			out = print_mode(val);
			break;
		case T_SOCKADDR:
			out = print_sockaddr(val);
			break;
		case T_FLAGS:
			out = print_flags(val);
			break;
		case T_PROMISC:
			out = print_promiscuous(val);
			break;
		case T_CAPABILITY:
			out = print_capabilities(val);
			break;
		case T_SUCCESS:
			out = print_success(val);
			break;
		case T_A0:
			out = print_a0(val, r);
			break;
		case T_A1:
			out = print_a1(val, r);
			break;
		case T_A2:
			out = print_a2(val, r);
			break; 
		case T_SIGNAL:
			out = print_signals(val);
			break; 
		default: {
			char *out2;
			if (comma)
				asprintf(&out2, "%s,", val);
			else
				out2 = strdup(val);
			out = out2;
			}
        }

	n = nvlist_get_cur(nv);
	n->interp_val = (char *)out;

	return out;
}
hidden_def(interpret);
