/*
 * aureport.c - main file for aureport utility 
 * Copyright 2005-06 Red Hat Inc., Durham, North Carolina.
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
 */

#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <locale.h>
#include "libaudit.h"
#include "auditd-config.h"
#include "aureport-options.h"
#include "aureport-scan.h"
#include "ausearch-lookup.h"


event very_first_event, very_last_event;
static FILE *log_fd = NULL;
static int found = 0;
static int process_logs(struct daemon_conf *config);
static int process_log_fd(const char *filename);
static int process_stdin(void);
static int process_file(char *filename);
static int get_record(llist *);
static void extract_timestamp(const char *b, event *e);
static int str2event(char *s, event *e);
static int events_are_equal(event *e1, event *e2);

extern char *user_file;

static int input_is_pipe(void)
{
	struct stat st;

	if (fstat(0, &st) == 0) {
		if (S_ISFIFO(st.st_mode))
			return 1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	struct daemon_conf config;
	struct rlimit limit;
	int rc;

	/* Check params and build regexpr */
	setlocale (LC_ALL, "");
	if (check_params(argc, argv))
		return 1;

	/* Raise the rlimits in case we're being started from a shell
	* with restrictions. Not a fatal error.  */
	limit.rlim_cur = RLIM_INFINITY;
	limit.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_FSIZE, &limit);
	setrlimit(RLIMIT_CPU, &limit);
	set_aumessage_mode(MSG_STDERR, DBG_NO);
	(void) umask( umask( 077 ) | 027 );
	very_first_event.sec = 0;
	reset_counters();

	if (user_file == NULL) {
		/* Load config so we know where logs are */
        	if (load_config(&config, TEST_SEARCH))
			fprintf(stderr, 
				"NOTE - using built-in logs: %s\n",
				config.log_file);
	} else {
		config.sender_ctx = NULL;
		config.log_file = NULL;
		config.dispatcher = NULL;
		config.action_mail_acct = NULL;
	}
		
	print_title();
	if (input_is_pipe())
		rc = process_stdin();
	else if (user_file)
		rc = process_file(user_file);
	else
		rc = process_logs(&config);
	if (rc) {
		free_config(&config); 
		return rc;
	}

	if (!found && report_detail == D_DETAILED && report_type != RPT_TIME) {
		printf("<no events of interest were found>\n\n");
		destroy_counters();
		free_config(&config); 
		return 1;
	} else 
		print_wrap_up();
	destroy_counters();
	aulookup_destroy_uid_list();
	aulookup_destroy_gid_list();
	free_config(&config); 
	free(user_file);
	return 0;
}

static int process_logs(struct daemon_conf *config)
{
	char *filename;
	int len, num = 0;


	/* for each file */
	len = strlen(config->log_file) + 16;
	filename = malloc(len);
	if (!filename) {
		fprintf(stderr, "No memory\n");
		return 1;
	}
	/* Find oldest log file */
	snprintf(filename, len, "%s", config->log_file);
	do {
		if (access(filename, R_OK) != 0)
			break;
		num++;
		snprintf(filename, len, "%s.%d", config->log_file, num);
	} while (1);
	num--;

	/* Got it, now process logs from last to first */
	if (num > 0)
		snprintf(filename, len, "%s.%d", config->log_file, num);
	else
		snprintf(filename, len, "%s", config->log_file);
	do {
		int ret;
		if ((ret = process_file(filename))) {
			free(filename);
			return ret;
		}

		/* Get next log file */
		num--;
		if (num > 0)
			snprintf(filename, len, "%s.%d", config->log_file, num);
		else if (num == 0)
			snprintf(filename, len, "%s", config->log_file);
		else
			break;
	} while (1);
	free(filename);
	return 0;
}

static int process_log_fd(const char *filename)
{
	llist entries; // entries in a record
	int ret;
	int first = 0;
	event first_event, last_event;

	last_event.sec = 0;
	last_event.milli = 0;

	/* For each record in file */
	list_create(&entries);
	do {
		ret = get_record(&entries);
		if ((ret < 0)||(entries.cnt == 0))
			break;
		// If report is RPT_TIME or RPT_SUMMARY, get 
		if (report_type <= RPT_SUMMARY) {
			if (first == 0) {
				list_get_event(&entries, &first_event);
				first = 1;
				if (very_first_event.sec == 0)
					list_get_event(&entries,
							&very_first_event);
			}
			list_get_event(&entries, &last_event);
		} 
		if (scan(&entries)) {
			// This is the per entry action item
			if (per_event_processing(&entries))
				found = 1;
		}
		list_clear(&entries);
	} while (ret == 0);
	fclose(log_fd);
	// This is the per file action items
	very_last_event.sec = last_event.sec;
	very_last_event.milli = last_event.milli;
	if (report_type == RPT_TIME) {
		if (first == 0) {
			printf("%s: no records\n", filename);
		} else {
			struct tm *btm;
			char tmp[32];

			printf("%s: ", filename);
			btm = localtime(&first_event.sec);
			strftime(tmp, sizeof(tmp), "%x %T", btm);
			printf("%s.%03d - ", tmp, first_event.milli);
			btm = localtime(&last_event.sec);
			strftime(tmp, sizeof(tmp), "%x %T", btm);
			printf("%s.%03d\n", tmp, last_event.milli);
		}
	}

	return 0;
}

static int process_stdin(void)
{
	log_fd = stdin;

	return process_log_fd("stdin");
}

static int process_file(char *filename)
{
	log_fd = fopen(filename, "r");
	if (log_fd == NULL) {
		fprintf(stderr, "Error opening %s (%s)\n", filename, 
			strerror(errno));
		return 1;
	}

	return process_log_fd(filename);
}

/*
 * This function returns a malloc'd buffer of the next record in the audit
 * logs. It returns 0 on success, 1 on eof, -1 on error. 
 */
static char *saved_buff = NULL;
static int get_record(llist *l)
{
// FIXME: this code needs to be re-organized to keep a linked list of record
// lists. Each time a new record is read, it should be checked to see if it 
// belongs to a list of records that is waiting for its terminal record. If
// so append to list. If the new record is a terminal type, return the list.
// If it does not belong to a list and it is not a terminal record, append the
// record to a new list of records. 
	char *rc;
	char *buff = NULL;
	int first_time = 1;

	while (1) {
		if (saved_buff) {
			buff = saved_buff;
			rc = buff;
			saved_buff = NULL;
		} else {
			if (!buff) {
				buff = malloc(MAX_AUDIT_MESSAGE_LENGTH);
				if (!buff)
					return -1;
			}
			rc = fgets_unlocked(buff, MAX_AUDIT_MESSAGE_LENGTH,
					log_fd);
		}
		if (rc) {
			lnode n;
			event e;
			char *ptr;

			ptr = strrchr(buff, 0x0a);
			if (ptr)
				*ptr = 0;
			n.message=strdup(buff);
			extract_timestamp(buff, &e);
			if (first_time) {
				l->e.milli = e.milli;
				l->e.sec = e.sec;
				l->e.serial = e.serial;
				first_time = 0;
			}
			if (events_are_equal(&l->e, &e)) { 
				list_append(l, &n);
			} else {
				saved_buff = buff;
				free(n.message);
				break;
			}
		} else {
			free(buff);
			if (feof(log_fd))
				return 1;
			else 
				return -1;
		}
	}
	if (!saved_buff)
		free(buff);
	return 0;
}

/*
 * This function will look at the line and pick out pieces of it.
 */
static void extract_timestamp(const char *b, event *e)
{
	char *ptr, *tmp;

	tmp = strndupa(b,80);
	ptr = strtok(tmp, " ");
	if (ptr) {
		// at this point we have type=
		ptr = strtok(NULL, " ");
		if (ptr) {
			if (*(ptr+9) == '(')
				ptr += 9;
			else
				ptr = strchr(ptr, '(');
			if (ptr) {
			// now we should be pointed at the timestamp
				char *eptr;
				ptr++;
				eptr = strchr(ptr, ')');
				if (eptr)
					*eptr = 0;
				if (str2event(ptr, e)) {
					fprintf(stderr,
					  "Error extracting time stamp (%s)\n",
					  ptr);
				}
			}
			// else we have a bad line
		}
		// else we have a bad line
	}
	// else we have a bad line
}

static int str2event(char *s, event *e)
{
	char *ptr;

	errno = 0;
	ptr = strchr(s+10, ':');
	if (ptr) {
		e->serial = strtoul(ptr+1, NULL, 10);
		*ptr = 0;
		if (errno)
			return -1;
	} else
		e->serial = 0;
	ptr = strchr(s, '.');
	if (ptr) {
		e->milli = strtoul(ptr+1, NULL, 10);
		*ptr = 0;
		if (errno)
			return -1;
	} else
		e->milli = 0;
	e->sec = strtoul(s, NULL, 10);
	if (errno)
		return -1;
	return 0;
}

static int events_are_equal(event *e1, event *e2)
{
	if (e1->serial == e2->serial && e1->milli == e2->milli &&
			e1->sec == e2->sec)
		return 1;
	else
		return 0;
}

