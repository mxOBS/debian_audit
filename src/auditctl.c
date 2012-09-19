/* auditctl.c -- 
 * Copyright 2004-2006 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *     Steve Grubb <sgrubb@redhat.com>
 *     Rickard E. (Rik) Faith <faith@redhat.com>
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>	/* strdup needs xopen define */
#include <getopt.h>
#include <time.h>
#include <sys/stat.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>	/* For basename */
#include "libaudit.h"
#include "private.h"

/* This define controls how many rule options we will allow when
 * reading a rule from a file. 64 fields are allowed by the kernel, so I
 * want to allow that plus a few entries for lists and other such items */
#define NUM_OPTIONS 72

/* This define controls the size of the line that we will request when
 * reading in rules from a file. We need to allow 64 fields. 25 bytes is 
 * the largest syscall name, so lets allow 1600 per line. 
 * Unrealistic - I know. 
 */
#define LINE_SIZE 1600


/* Global functions */
static int handle_request(int status);
static void get_reply(void);
static int audit_print_reply(struct audit_reply *rep);
extern int delete_all_rules(int fd);

/* Global vars */
static int fd = -1;
static int list_requested = 0;
static int add = AUDIT_FILTER_UNSET, del = AUDIT_FILTER_UNSET, action = 0;
static int ignore = 0;
static int exclude = 0, msgtype_cnt = 0;
enum { OLD, NEW };
int which;
static struct audit_rule  rule;
static struct audit_rule_data *rule_new = NULL;

extern int audit_archadded;
extern int audit_syscalladded;
extern unsigned int audit_elf;

/*
 * This function will reset everything used for each loop when loading 
 * a ruleset from a file.
 */
static int reset_vars(void)
{
	list_requested = 0;
	audit_syscalladded = 0;
	audit_archadded = 0;
	audit_elf = 0;
	add = AUDIT_FILTER_UNSET;
	del = AUDIT_FILTER_UNSET;
	action = 0;
	exclude = 0;
	msgtype_cnt = 0;
	which = OLD;

	memset(&rule, 0, sizeof(rule));
	free(rule_new);
	rule_new = NULL;
	if ((fd = audit_open()) < 0) {
		fprintf(stderr, "Cannot open netlink audit socket\n");
		return 1;
	}
	return 0;
}

static void upgrade_rule(void)
{
	int i;

	rule_new=malloc(sizeof(struct audit_rule_data));
	memset(rule_new, 0, sizeof(struct audit_rule_data));
	memcpy(rule_new, &rule, sizeof(rule));
	which = NEW;
	if (rule_new->field_count == 0)
		return;

	// now go through fields and move legacy ops to fieldflags
	for (i=0; i<rule_new->field_count; i++) {
		uint32_t ops = rule_new->fields[i] & 
				(AUDIT_NEGATE|AUDIT_OPERATORS);
		rule_new->fields[i] &= ~(AUDIT_NEGATE|AUDIT_OPERATORS);
		if (ops & AUDIT_NEGATE)
			rule_new->fieldflags[i] = AUDIT_NOT_EQUAL;
		else
			rule_new->fieldflags[i] = AUDIT_EQUAL;
	}
}

static void usage(void)
{
    printf(
    "usage: auditctl [options]\n"
     "    -a <l,a>     Append rule to end of <l>ist with <a>ction\n"
     "    -A <l,a>     Add rule at beginning of <l>ist with <a>ction\n"
     "    -b <backlog> Set max number of outstanding audit buffers allowed\n"
     "                 Default=64\n"
     "    -d <l,a>     Delete rule from <l>ist with <a>ction\n"
     "                 l=task,entry,exit,user,watch,exclude a=never,possible,always\n"
     "    -D           Delete all rules and watches\n"
     "    -e [0..2]    Set enabled flag\n"
     "    -f [0..2]    Set failure flag\n"
     "                 0=silent 1=printk 2=panic\n"
     "    -F f=v       Build rule: field name, operator(=,!=,<,>,<=,>=,^,&),\n"
     "                 value\n"
     "    -h           Help\n"
     "    -i           Ignore errors when reading rules from file\n"
     "    -k <key>     Set filter key on audit rule\n"
     "    -l           List rules\n"
     "    -m text      Send a user-space message\n"
     "    -p [r|w|x|a] Set permissions filter on watch\n"
     "                 r=read, w=write, x=execute, a=attribute\n"
     "    -r <rate>    Set limit in messages/sec (0=none)\n"
     "    -R <file>    read rules from file\n"
     "    -s           Report status\n"
     "    -S syscall   Build rule: syscall name or number\n"
     "    -v           Version\n"
     "    -w <path>    Insert watch at <path>\n"
     "    -W <path>    Remove watch at <path>\n"
     );
}

/* Returns 0 ok, 1 deprecated action, 2 error */
static int audit_rule_setup(const char *opt, int *flags, int *act)
{
	if (strstr(opt, "task")) 
		*flags = AUDIT_FILTER_TASK;
	else if (strstr(opt, "entry"))
		*flags = AUDIT_FILTER_ENTRY;
	else if (strstr(opt, "exit"))
		*flags = AUDIT_FILTER_EXIT;
	else if (strstr(opt, "user"))
		*flags = AUDIT_FILTER_USER;
	else if (strstr(opt, "exclude")) {
		*flags = AUDIT_FILTER_EXCLUDE;
		exclude = 1;
	} else
		return 2;
	if (strstr(opt, "never"))
		*act = AUDIT_NEVER;
	else if (strstr(opt, "possible"))
		return 1;
	else if (strstr(opt, "always"))
		*act = AUDIT_ALWAYS;
	else
		return 2;
	return 0;
}

/*
 * This function will check the path before accepting it. It returns
 * 1 on error and 0 on success.
 */
static int check_path(const char *path)
{
	char *ptr, *base;
	size_t nlen;
	size_t plen = strlen(path);
	if (plen >= PATH_MAX) {
		fprintf(stderr, "The path passed for the watch is too big\n");
		return 1;
	}
	if (path[0] != '/') {
		fprintf(stderr, "The path must start with '/'\n");
		return 1;
	}
	ptr = strdup(path);
	base = basename(ptr);
	nlen = strlen(base);
	free(ptr);
	if (nlen > NAME_MAX) {
		fprintf(stderr, "The base name of the path is too big\n");
		return 1;
	}

	/* These are warnings, not errors */
	if (strstr(path, ".."))
		fprintf(stderr, 
			"Warning - relative path notation is not supported\n");
	if (strchr(path, '*') || strchr(path, '?'))
		fprintf(stderr, 
			"Warning - wildcard notation is not supported\n");

	return 0;
}

/*
 * Setup a watch.  The "name" of the watch in userspace will be the <path> to
 * the watch.  When this potential watch reaches the kernel, it will resolve
 * down to <name> (of terminating file or directory). 
 * Returns a 1 on success & -1 on failure.
 */
static int audit_setup_watch_name(struct audit_rule_data **rulep, char *path)
{
	size_t len;

	if (check_path(path))
		return -1;

	// Trim trailing '/' should they exist
	len = strlen(path);
	if (len > 2 && path[len-1] == '/') {
		while (path[len-1] == '/' && len > 1) {
			path[len-1] = 0;
			len--;
		}
	}

	/* FIXME: might want to check to see that rule is empty */
	if (audit_add_watch(rulep, path)) 
		return -1;

	return 1;
}

/*
 * Setup a watch permissions.
 * Returns a 1 on success & -1 on failure.
 */
static int audit_setup_perms(struct audit_rule_data *rule, const char *opt)
{
	unsigned int i, len, val = 0;

	len = strlen(opt);
	if (len > 4)
		return -1;

	for (i = 0; i < len; i++) {
		switch (tolower(opt[i])) {
			case 'r':
				val |= AUDIT_PERM_READ;
				break;
			case 'w':
				val |= AUDIT_PERM_WRITE;
				break;
			case 'x':
				val |= AUDIT_PERM_EXEC;
				break;
			case 'a':
				val |= AUDIT_PERM_ATTR;
				break;
			default:
				fprintf(stderr,
					"Permission %c isn't supported\n",
					opt[i]);
				return -1;
		}
	}

	if (audit_update_watch_perms(rule, val) == 0)
		return 1;
	return -1;
}


void audit_request_rule_list(int fd)
{
	int rc;

	/* Try out the new message type */
	if ((rc = audit_request_rules_list_data(fd)) > 0) {
		list_requested = 1;
		get_reply();
	} else if (rc == -EINVAL) { /* Not supported...drop back to old one */
		if (audit_request_rules_list(fd) > 0) {
			list_requested = 1;
			get_reply();
		}
	}
}
// FIXME: Change these to enums
/*
 * returns: -3 depreacted, -2 success - no reply, -1 error - noreply,
 * 0 success - reply, > 0 success - rule
 */
static int setopt(int count, char *vars[])
{
    int c;
    int retval = 0, rc;

    optind = 0;
    opterr = 0;
    while ((retval >= 0) && (c = getopt(count, vars,
			"hislDve:f:r:b:a:A:d:S:F:m:R:w:W:k:p:")) != EOF) {
	int flags = AUDIT_FILTER_UNSET;
	rc = 10;	// Init to something impossible to see if unused.
        switch (c) {
        case 'h':
		usage();
		retval = -1;
		break;
	case 'i':
		ignore = 1;
		break;
        case 's':
		retval = audit_request_status(fd);
		if (retval <= 0)
			retval = -1;
		else
			retval = 0; /* success - just get the reply */
		break;
        case 'e':
		if (optarg && ((strcmp(optarg, "0") == 0) ||
				(strcmp(optarg, "1") == 0) ||
				(strcmp(optarg, "2") == 0))) {
			if (audit_set_enabled(fd, strtoul(optarg,NULL,0)) > 0)
				audit_request_status(fd);
			else
				retval = -1;
		} else {
			fprintf(stderr, "Enable must be 0, 1, or 2 was %s\n", 
				optarg);
			retval = -1;
		}
		break;
        case 'f':
		if (optarg && ((strcmp(optarg, "0") == 0) ||
				(strcmp(optarg, "1") == 0) ||
				(strcmp(optarg, "2") == 0))) {
			if (audit_set_failure(fd, strtoul(optarg,NULL,0)) > 0)
				audit_request_status(fd);
			else
				return -1;
		} else {
			fprintf(stderr, "Failure must be 0, 1, or 2 was %s\n", 
				optarg);
			retval = -1;
		}
		break;
        case 'r':
		if (optarg && isdigit(optarg[0])) { 
			uint32_t rate;
			errno = 0;
			rate = strtoul(optarg,NULL,0);
			if (errno) {
				fprintf(stderr, "Error converting rate\n");
				return -1;
			}
			if (audit_set_rate_limit(fd, rate) > 0)
				audit_request_status(fd);
			else
				return -1;
		} else {
			fprintf(stderr, "Rate must be a numeric value was %s\n",
				optarg);
			retval = -1;
		}
		break;
        case 'b':
		if (optarg && isdigit(optarg[0])) {
			uint32_t limit;
			errno = 0;
			limit = strtoul(optarg,NULL,0);
			if (errno) {
				fprintf(stderr, "Error converting backlog\n");
				return -1;
			}
			if (audit_set_backlog_limit(fd, limit) > 0)
				audit_request_status(fd);
			else
				return -1;
		} else {
			fprintf(stderr, 
				"Backlog must be a numeric value was %s\n", 
				optarg);
			retval = -1;
		}
		break;
        case 'l':
		if (count != 2) {
			fprintf(stderr,
				"List request should be given by itself\n");
			retval = -1;
			break;
		}
		audit_request_rule_list(fd);
		retval = -2;
		break;
        case 'a':
		if (strstr(optarg, "task") && audit_syscalladded) {
			fprintf(stderr, 
				"Syscall auditing requested for task list\n");
			retval = -1;
		} else {
			rc = audit_rule_setup(optarg, &add, &action);
			if (rc > 1) {
				fprintf(stderr, 
					"Append rule - bad keyword %s\n",
					optarg);
				retval = -1;
			} else if (rc == 1) {
				fprintf(stderr, 
				    "Append rule - possible is deprecated\n");
				return -3; /* deprecated - eat it */
			} else
				retval = 1; /* success - please send */
		}
		break;
        case 'A': 
		if (strstr(optarg, "task") && audit_syscalladded) {
			fprintf(stderr, 
			   "Error: syscall auditing requested for task list\n");
			retval = -1;
		} else {
			rc = audit_rule_setup(optarg, &add, &action);
			if (rc > 1) {
				fprintf(stderr,
				"Add rule - bad keyword %s\n", optarg);
				retval = -1;
			} else if (rc == 1) {
				fprintf(stderr, 
				    "Append rule - possible is deprecated\n");
				return -3; /* deprecated - eat it */
			} else {
				add |= AUDIT_FILTER_PREPEND;
				retval = 1; /* success - please send */
			}
		}
		break;
        case 'd': 
		rc = audit_rule_setup(optarg, &del, &action);
		if (rc > 1) {
			fprintf(stderr, "Delete rule - bad keyword %s\n", 
				optarg);
			retval = -1;
		} else if (rc == 1) {
			fprintf(stderr, 
			    "Delete rule - possible is deprecated\n");
			return -3; /* deprecated - eat it */
		} else
			retval = 1; /* success - please send */
		break;
        case 'S':
		/* Do some checking to make sure that we are not adding a
		 * syscall rule to a list that does not make sense. */
		if (((add & (AUDIT_FILTER_MASK|AUDIT_FILTER_UNSET)) ==
				AUDIT_FILTER_TASK || (del & 
				(AUDIT_FILTER_MASK|AUDIT_FILTER_UNSET)) == 
				AUDIT_FILTER_TASK)) {
			fprintf(stderr, 
			  "Error: syscall auditing being added to task list\n");
			return -1;
		} else if (((add & (AUDIT_FILTER_MASK|AUDIT_FILTER_UNSET)) ==
				AUDIT_FILTER_USER || (del &
				(AUDIT_FILTER_MASK|AUDIT_FILTER_UNSET)) ==
				AUDIT_FILTER_USER)) {
			fprintf(stderr, 
			  "Error: syscall auditing being added to user list\n");
			return -1;
		} else if (exclude) {
			fprintf(stderr, 
		    "Error: syscall auditing cannot be put on exclude list\n");
			return -1;
		} else {
			if (!audit_elf) {
				int machine;
				unsigned int elf;
				machine = audit_detect_machine();
				if (machine < 0) {
					fprintf(stderr, 
					    "Error detecting machine type");
					return -1;
				}
				elf = audit_machine_to_elf(machine);
                                if (elf == 0) {
					fprintf(stderr, 
					    "Error looking up elf type");
					return -1;
				}
				audit_elf = elf;
			}
		}
		if (which == OLD) 
			rc = audit_rule_syscallbyname(&rule, optarg);
		else
			rc = audit_rule_syscallbyname(
				(struct audit_rule *)rule_new, optarg);
		switch (rc)
		{
			case 0:
				audit_syscalladded = 1;
				break;
			case -1:
				fprintf(stderr, "Syscall name unknown: %s\n", 
							optarg);
				retval = -1;
				break;
			case -2:
				fprintf(stderr, "Elf type unknown: 0x%x\n", 
							audit_elf);
				retval = -1;
				break;
		}
		break;
        case 'F':
		if (add != AUDIT_FILTER_UNSET)
			flags = add & AUDIT_FILTER_MASK;
		else if (del != AUDIT_FILTER_UNSET)
			flags = del & AUDIT_FILTER_MASK;
		// if the field is arch & there is a -t option...we 
		// can allow it
		else if ((optind >= count) || (strstr(optarg, "arch=") == NULL)
				 || (strcmp(vars[optind], "-t") != 0)) {
			fprintf(stderr, "List must be given before field\n");
			retval = -1;
			break;
		}
		if (strncmp(optarg, "msgtype=", 7) == 0) {
			if (msgtype_cnt) {
				fprintf(stderr, 
				    "Only one msgtype may be given per rule\n");
				retval = -1;
				break;
			} else
				msgtype_cnt++;
		}
		if (which == OLD) {
			char *ptr = strdup(optarg);
			rc = audit_rule_fieldpair(&rule, ptr, flags);
			if (rc == -10)
				upgrade_rule(); /* need to upgrade... */
			free(ptr);
		}
		if (which == NEW) 
			rc = audit_rule_fieldpair_data(&rule_new,optarg,flags);
//FIXME: make this a function
		switch (rc)
		{
			case 0:
				break;
			case -1:
				fprintf(stderr, "-F missing = for %s\n", 
					optarg);
				retval = -1;
				break;
			case -2:
				fprintf(stderr, "-F unknown field: %s\n", 
					optarg);
				retval = -1;
				break;
			case -3:
				fprintf(stderr, 
					"-F %s must be before -S\n", 
					optarg);
				retval = -1;
				break;
			case -4:
				fprintf(stderr, 
					"-F %s machine type not found\n", 
					optarg);
				retval = -1;
				break;
			case -5:
				fprintf(stderr, 
					"-F %s elf mapping not found\n", 
					optarg);
				retval = -1;
				break;
			case -6:
				fprintf(stderr, 
			"-F %s requested bit level not supported by machine\n", 
					optarg);
				retval = -1;
				break;
			case -7:
				fprintf(stderr,
			 "Field %s cannot be checked at syscall entry\n",
					 optarg);
				retval = -1;
				break;
			case -8:
				fprintf(stderr, 
					"-F unknown message type - %s\n",
					 optarg);
				retval = -1;
				break;
			case -9:
				fprintf(stderr,
		 "msgtype field can only be used with exclude filter list\n");
				retval = -1;
				break;
			case -10:
				fprintf(stderr,
					"Failed upgrading rule\n");
				retval = -1;
			case -11:
				fprintf(stderr,
					"String value too long\n");
				retval = -1;
				break;
			case -12:
				fprintf(stderr,
			"Only msgtype field can be used with exclude filter\n");
				retval = -1;
				break;
			case -13:
				fprintf(stderr,
			"Field (%s) only takes = or != operators\n", optarg);
				retval = -1;
				break;
			case -14:
				fprintf(stderr,
				"Permission (%s) can only contain \'rwxa\n",
					optarg);
				retval = -1;
				break;
			default:
				retval = -1;
				break;
		}
		break;
        case 'm':
		if (audit_log_user_message( fd, AUDIT_USER, optarg, NULL, 
				NULL, NULL, 1) <=0)
			retval = -1;
		else
			return -2;  // success - no reply for this
		break;
	case 'R':
		fprintf(stderr, "Error - nested rule files not supported\n");
		retval = -1;
		break;
	case 'D':
		if (count != 2) {
			fprintf(stderr,
			    "Delete all request should be given by itself\n");
			retval = -1;
			break;
		}
		retval = delete_all_rules(fd);
		if (retval == 0) {
			audit_request_rule_list(fd);
			retval = -2;
		}
		break;
	case 'w':
		if (optarg) { 
			add = AUDIT_FILTER_EXIT;
			action = AUDIT_ALWAYS;
			which = NEW;
			audit_syscalladded = 1;
			retval = audit_setup_watch_name(&rule_new, optarg);
		} else {
			fprintf(stderr, "watch option needs a path\n");	
			retval = -1;
		}
		break;
	case 'W':
		if (optarg) { 
			del = AUDIT_FILTER_EXIT;
			action = AUDIT_ALWAYS;
			which = NEW;
			audit_syscalladded = 1;
			retval = audit_setup_watch_name(&rule_new, optarg);
		} else {
			fprintf(stderr, "watch option needs a path\n");	
			retval = -1;
		}
		break;
	case 'k':
		if (audit_syscalladded != 1 ||
				(add==AUDIT_FILTER_UNSET &&
					del==AUDIT_FILTER_UNSET)) {
			fprintf(stderr,
			"key option needs a watch or syscall given prior to it\n");
			retval = -1;
		} else if (!optarg) {
			fprintf(stderr, "key option needs a value\n");
			retval = -1;
		} else {
			int flags = 0;
			char *cmd=NULL;

			/* Get the flag */
			if (add != AUDIT_FILTER_UNSET)
				flags = add & AUDIT_FILTER_MASK;
			else if (del != AUDIT_FILTER_UNSET)
				flags = del & AUDIT_FILTER_MASK;

			/* Build the command */
			asprintf(&cmd, "key=%s", optarg);
			if (cmd) {
				/* Add this to the rule */
				int ret;
				if (which == OLD)
					upgrade_rule();
				ret = audit_rule_fieldpair_data(&rule_new,
					cmd, flags);
				if (ret < 0)
					retval = -1;
				free(cmd);
			} else {
				fprintf(stderr, "Out of memory adding key\n");
				retval = -1;
			}
		}
		break;
	case 'p':
		if (!add && !del) {
			fprintf(stderr,
			"permission option needs a watch given prior to it\n");
			retval = -1;
		} else if (!optarg) {
			fprintf(stderr, "permission option needs a filter\n");
			retval = -1;
		} else {
			if (which == OLD) {
				fprintf(stderr,
				"You must give a watch prior to perms\n");
				retval = -1;
			} else
				retval = audit_setup_perms(rule_new, optarg);
		}
		break;
	case 'v':
		printf("auditctl version %s\n", VERSION);
		retval = -2;
		break;
        default: 
		usage();
		retval = -1;
		break;
        }
    }
    /* catch extra args or errors where the user types "- s" */
    if (optind == 1)
	retval = -1;
    else if ((optind < count) && (retval != -1)) {
	fprintf(stderr, "parameter passed without an option given\n");	
	retval = -1;
    }
    return retval;
}

static char *get_line(FILE *f, char *buf)
{
	if (fgets_unlocked(buf, LINE_SIZE, f)) {
		/* remove newline */
		char *ptr = strchr(buf, 0x0a);
		if (ptr)
			*ptr = 0;
		return buf;
	}
	return NULL;
}

/*
 * This function reads the given file line by line and executes the rule.
 * It returns 0 if everything went OK, 1 if there are problems before reading
 * the file and -1 on error conditions after executing some of the rules.
 * It will abort reading the file if it encounters any problems.
 */
static int fileopt(const char *file)
{
	int i, tfd, rc, lineno = 1;
	struct stat st;
        FILE *f;
        char buf[LINE_SIZE];

	/* Does the file exist? */
	rc = open(file, O_RDONLY);
	if (rc < 0) {
		if (errno != ENOENT) {
			fprintf(stderr,"Error opening %s (%s)\n", 
				file, strerror(errno));
                        return 1;
                }
                fprintf(stderr, "file %s doesn't exist, skipping\n", file);
                return 0;
        }
        tfd = rc;

	/* Is the file permissions sane? */
	if (fstat(tfd, &st) < 0) {
		fprintf(stderr, "Error fstat'ing %s (%s)\n",
			file, strerror(errno));
		close(tfd);
		return 1;
	}
	if (st.st_uid != 0) {
		fprintf(stderr, "Error - %s isn't owned by root\n", file);
		close(tfd);
		return 1;
	} 
	if ((st.st_mode & S_IWOTH) == S_IWOTH) {
		fprintf(stderr, "Error - %s is world writable\n", file);
		close(tfd);
		return 1;
	}
	if (!S_ISREG(st.st_mode)) {
		fprintf(stderr, "Error - %s is not a regular file\n", file);
		close(tfd);
		return 1;
	}

        f = fdopen(tfd, "r");
        if (f == NULL) {
                fprintf(stderr, "Error - fdopen failed (%s)\n",
                        strerror(errno));
		close(tfd);
                return 1;
        }

	/* Read until eof, lineno starts as 1 */
	while (get_line(f, buf)) {
		char *options[NUM_OPTIONS];
		char *ptr;
		int idx=0;

		/* Weed out blank lines */
		while (buf[idx] == ' ')
			idx++;
		if (buf[idx] == 0) {
			lineno++;
			continue;
		}
		ptr = strtok(buf, " ");
		if (ptr == NULL)
			break;
		/* allow comments */
		if (ptr[0] == '#') {
			lineno++;
			continue;
		}
		i = 0;
		options[i++] = "auditctl";
		options[i++] = ptr;
		while( (ptr=strtok(NULL, " ")) && i<NUM_OPTIONS-1 ) {
			options[i++] = ptr;
		}
		options[i] = NULL;

		/* Parse it */
		if (reset_vars()) {
			fclose(f);
			return -1;
		}
		rc = setopt(i, options);

		/* handle reply or send rule */
		if (rc != -3) {
			if (handle_request(rc) == -1) {
				if (errno != ECONNREFUSED)
					fprintf(stderr,
					"There was an error in line %d of %s\n",
					lineno, file);
				if (!ignore) {
					fclose(f);
					return -1;
				}
			}
		}
		lineno++;
	}
	fclose(f);
	return 0;
}

int main(int argc, char *argv[])
{
	int retval = 1;

	set_aumessage_mode(MSG_STDERR, DBG_NO);

	/* Check where the rules are coming from: commandline or file */
	if ((argc == 3) && (strcmp(argv[1], "-R") == 0)) {
#ifndef DEBUG
		/* Make sure we are root */
		if (getuid() != 0) {
			fprintf(stderr, 
				"You must be root to run this program.\n");
			return 4;
		}
#endif
		if (fileopt(argv[2]))
			return 1;
		else
			return 0;
	} else {
		if (argc == 1) {
			usage();
			return 1;
		}
#ifndef DEBUG
		/* Make sure we are root */
		if (getuid() != 0) {
			fprintf(stderr, 
				"You must be root to run this program.\n");
			return 4;
		}
#endif
		if (reset_vars())
			return 1;
		retval = setopt(argc, argv);
		if (retval == -3)
			return 0;
	}
	return handle_request(retval);
}

/*
 * This function is called after setopt to handle the return code.
 * On entry, status = 0 means just get the reply. Greater than 0 means we
 * are adding or deleting a rule or watch. -1 means an error occurred.
 * -2 means everything is OK and no reply needed. Even if there's an 
 * error, we need to call this routine to close up the audit fd.
 * The return code from this function is 0 success and -1 error.
 */
static int handle_request(int status)
{
	if (status == 0) {
		if (audit_syscalladded) {
			fprintf(stderr, "Error - no list specified\n");
			return -1;
		}
		get_reply();
	} else if (status == -2)
		status = 0;  // report success 
	else if (status > 0) {
		int rc;
		if (add != AUDIT_FILTER_UNSET) {
			// if !task add syscall any if not specified
			if ((add & AUDIT_FILTER_MASK) != AUDIT_FILTER_TASK && 
					audit_syscalladded != 1) {
				if (which == OLD)
					audit_rule_syscallbyname(&rule, "all");
				else
					audit_rule_syscallbyname_data(
							rule_new, "all");
			}
			if (which == OLD) {
				rc = audit_add_rule(fd, &rule, add, action);
			} else {
				rc = audit_add_rule_data(fd, rule_new,
								 add, action);
			}
		}
		else if (del != AUDIT_FILTER_UNSET) {
			if ((del & AUDIT_FILTER_MASK) != AUDIT_FILTER_TASK && 
					audit_syscalladded != 1) {
				if (which == OLD)
					audit_rule_syscallbyname(&rule, "all");
				else
					audit_rule_syscallbyname_data(
							rule_new, "all");
			}
			if (which == OLD)
				rc = audit_delete_rule(fd, &rule, del, action);
			else
				rc = audit_delete_rule_data(fd, rule_new,
								 del, action);
		} else {
        		usage();
	    		audit_close(fd);
			exit(1);
	    	}
		if (rc <= 0) 
			status = -1;
		else
			status = 0;
	} else 
		status = -1;

	audit_close(fd);
	fd = -1;
	return status;
}

/*
 * A reply from the kernel is expected. Get and display it.
 */
static void get_reply(void)
{
	int i, retval;
	int timeout = 40; /* loop has delay of .1 - so this is 4 seconds */
	struct audit_reply rep;
	fd_set read_mask;
	FD_ZERO(&read_mask);
	FD_SET(fd, &read_mask);

	for (i = 0; i < timeout; i++) {
		struct timeval t;

		t.tv_sec  = 0;
		t.tv_usec = 100000; /* .1 second */
		do {
			retval=select(fd+1, &read_mask, NULL, NULL, &t);
		} while (retval < 0 && errno == EINTR);
		// We'll try to read just in case
		retval = audit_get_reply(fd, &rep, GET_REPLY_NONBLOCKING, 0);
		if (retval > 0) {
			if (rep.type == NLMSG_ERROR && rep.error->error == 0) {
				i = 0;    /* reset timeout */
				continue; /* This was an ack */
			}
			
			if ((retval = audit_print_reply(&rep)) == 0) 
				break;
			if (retval == 1)
				i = 0; /* If getting more, reset timeout */
		}
	}
}

/*
 * This function interprets the reply and prints it to stdout. It returns
 * 0 if no more should be read and 1 to indicate that more messages of this
 * type may need to be read. 
 */
static int audit_print_reply(struct audit_reply *rep)
{
	unsigned int i;
	int first;
	int sparse;
	int machine = audit_detect_machine();
	size_t boffset;
	int show_syscall;

	audit_elf = 0; 
	switch (rep->type) {
		case NLMSG_NOOP:
			return 1;
		case NLMSG_DONE:
			if (list_requested == 1)
				printf("No rules\n");
			return 0;
		case NLMSG_ERROR: 
		        printf("NLMSG_ERROR %d (%s)\n",
				-rep->error->error, 
				strerror(-rep->error->error));
			return 0;
		case AUDIT_GET:
			printf("AUDIT_STATUS: enabled=%d flag=%d pid=%d"
			" rate_limit=%d backlog_limit=%d lost=%d backlog=%d\n",
			rep->status->enabled, rep->status->failure,
			rep->status->pid, rep->status->rate_limit,
			rep->status->backlog_limit, rep->status->lost,
			rep->status->backlog);
			return 0;
		case AUDIT_LIST:
		case AUDIT_LIST_RULES:
			list_requested = 0;
			boffset = 0;
			show_syscall = 1;
			printf("%s: %s,%s", audit_msg_type_to_name(rep->type),
				audit_flag_to_name((int)rep->rule->flags),
				audit_action_to_name(rep->rule->action));

			for (i = 0; i < rep->rule->field_count; i++) {
				const char *name;
				int op;
				int field = rep->rule->fields[i] &
					~AUDIT_OPERATORS & ~AUDIT_NEGATE;
				if (rep->type == AUDIT_LIST_RULES) {
					op = rep->ruledata->fieldflags[i] &
					(AUDIT_OPERATORS | AUDIT_NEGATE);
				} else {
					op = rep->rule->fields[i] &
					    (AUDIT_OPERATORS | AUDIT_NEGATE);
				}
                
				name = audit_field_to_name(field);
				if (name) {
					if (strcmp(name, "arch") == 0) { 
						audit_elf =rep->rule->values[i];
						printf(" %s%s%u", name, 
							audit_operator_to_symbol(op),
							(unsigned)rep->rule->values[i]);
					}
					else if (strcmp(name, "msgtype") == 0) {
						if (!audit_msg_type_to_name(rep->rule->values[i]))
							printf(" %s%s%d", name,
								audit_operator_to_symbol(op),
								rep->rule->values[i]);
						else {
							printf(" %s%s%s", name,
								audit_operator_to_symbol(op),
								audit_msg_type_to_name(rep->rule->values[i]));
						}
					} else if ((field >= AUDIT_SUBJ_USER &&
						  field <= AUDIT_OBJ_LEV_HIGH)
						&& field != AUDIT_PPID &&
					       rep->type == AUDIT_LIST_RULES) {
						printf(" %s%s%.*s", name,
						  audit_operator_to_symbol(op),
						  rep->ruledata->values[i],
						  &rep->ruledata->buf[boffset]);
						boffset +=
						    rep->ruledata->values[i];
					} else if (field == AUDIT_WATCH) {
						printf(" watch=%.*s", 
						  rep->ruledata->values[i],
						  &rep->ruledata->buf[boffset]);
						boffset +=
						    rep->ruledata->values[i];
					} else if (field == AUDIT_FILTERKEY) {
						printf(" key=%.*s",
						rep->ruledata->values[i],
						&rep->ruledata->buf[boffset]);
						boffset +=
						    rep->ruledata->values[i];
					} else if (field == AUDIT_PERM) {
						char perms[5];
						int val=rep->rule->values[i];
						perms[0] = 0;
						if (val & AUDIT_PERM_READ)
							strcat(perms, "r");
						if (val & AUDIT_PERM_WRITE)
							strcat(perms, "w");
						if (val & AUDIT_PERM_EXEC)
							strcat(perms, "x");
						if (val & AUDIT_PERM_ATTR)
							strcat(perms, "a");
						printf(" perm=%s", perms);
						show_syscall = 0;
					} else {
						printf(" %s%s%d", name, 
							audit_operator_to_symbol(op),
							rep->rule->values[i]);
					}
				} else { 
					printf(" f%d%s%d", rep->rule->fields[i],
						audit_operator_to_symbol(op),
						rep->rule->values[i]);
				}
				/* Avoid printing value if the field type is 
				 * known to return a string. */
				if (rep->rule->values[i] && 
						(field < AUDIT_SUBJ_USER ||
						 field > AUDIT_SUBJ_CLR) &&
						field != AUDIT_WATCH &&
						field != AUDIT_FILTERKEY &&
						field != AUDIT_PERM)
					printf(" (0x%x)", rep->rule->values[i]);
			}
			if (show_syscall &&
				((rep->rule->flags & AUDIT_FILTER_MASK) != 
						AUDIT_FILTER_USER) &&
				((rep->rule->flags & AUDIT_FILTER_MASK) !=
						AUDIT_FILTER_TASK)) {
				printf(" syscall=");
				for (sparse = 0, i = 0; 
					i < (AUDIT_BITMASK_SIZE-1); i++) {
					if (rep->rule->mask[i] != (uint32_t)~0)
						sparse = 1;
				}
				if (!sparse) {
					printf("all");
				} else for (first = 1, i = 0;
					i < AUDIT_BITMASK_SIZE * 32; i++) {
					int word = AUDIT_WORD(i);
					int bit  = AUDIT_BIT(i);
					if (rep->rule->mask[word] & bit) {
						const char *ptr;
						if (audit_elf)
							machine = 
							audit_elf_to_machine(
								audit_elf);
						if (machine < 0)
							ptr = 0;
						else
							ptr = 
							audit_syscall_to_name(i, 
							machine);
						if (ptr)
							printf("%s%s", 
							first ? "" : ",", ptr);
						else
							printf("%s%d", 
							first ? "" : ",", i);
						first = 0;
					}
				}
			}
			printf("\n");
			return 1; /* get more messages until NLMSG_DONE */
		default:
			printf("Unknown: type=%d, len=%d\n", rep->type, 
				rep->nlh->nlmsg_len);
			return 0;
	}
}

