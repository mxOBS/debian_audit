/* remote-config.c -- 
 * Copyright 2008 Red Hat Inc., Durham, North Carolina.
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
 *   Steve Grubb <sgrubb@redhat.com>
 * 
 */

#include "config.h"
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <ctype.h>
#include <limits.h>
#include "remote-config.h"

/* Local prototypes */
struct nv_pair
{
	const char *name;
	const char *value;
	const char *option;
};

struct kw_pair 
{
	const char *name;
	int (*parser)(struct nv_pair *, int, remote_conf_t *);
	int max_options;
};

struct nv_list
{ 
	const char *name;
	int option;
};

static char *get_line(FILE *f, char *buf);
static int nv_split(char *buf, struct nv_pair *nv);
static const struct kw_pair *kw_lookup(const char *val);
static int server_parser(struct nv_pair *nv, int line, 
		remote_conf_t *config);
static int port_parser(struct nv_pair *nv, int line, 
		remote_conf_t *config);
static int transport_parser(struct nv_pair *nv, int line, 
		remote_conf_t *config);
static int mode_parser(struct nv_pair *nv, int line, 
		remote_conf_t *config);
static int depth_parser(struct nv_pair *nv, int line, 
		remote_conf_t *config);
static int fail_action_parser(struct nv_pair *nv, int line, 
		remote_conf_t *config);
static int sanity_check(remote_conf_t *config, const char *file);

static const struct kw_pair keywords[] = 
{
  {"remote_server",    server_parser,		0 },
  {"port",             port_parser,		0 },
  {"transport",        transport_parser,	0 },
  {"mode",             mode_parser,		0 },
  {"queue_depth",      depth_parser,		0 },
  {"fail_action",      fail_action_parser,	0 },
  { NULL,             NULL }
};

static const struct nv_list transport_words[] =
{
  {"tcp",  T_TCP  },
  { NULL,  0 }
};

static const struct nv_list mode_words[] =
{
  {"immediate",  M_IMMEDIATE },
  {"forward",    M_STORE_AND_FORWARD },
  { NULL,  0 }
};

static const struct nv_list fail_action_words[] =
{
  {"ignore",   F_IGNORE },
  {"syslog",   F_SYSLOG },
  {"exec",     F_EXEC },
  {"suspend",  F_SUSPEND },
  {"single",   F_SINGLE },
  {"halt",     F_HALT },
  { NULL,  0 }
};

/*
 * Set everything to its default value
*/
void clear_config(remote_conf_t *config)
{
	config->remote_server = NULL;
	config->port = 60;
	config->port = T_TCP;
	config->mode = M_IMMEDIATE;
	config->queue_depth = 20;
	config->fail_action = F_SYSLOG;
	config->fail_exe = NULL;
}

int load_config(remote_conf_t *config, const char *file)
{
	int fd, rc, mode, lineno = 1;
	struct stat st;
	FILE *f;
	char buf[128];

	clear_config(config);

	/* open the file */
	mode = O_RDONLY;
	rc = open(file, mode);
	if (rc < 0) {
		if (errno != ENOENT) {
			syslog(LOG_ERR, "Error opening %s (%s)", file,
				strerror(errno));
			return 1;
		}
		syslog(LOG_WARNING,
			"Config file %s doesn't exist, skipping", file);
		return 0;
	}
	fd = rc;

	/* check the file's permissions: owned by root, not world writable,
	 * not symlink.
	 */
	if (fstat(fd, &st) < 0) {
		syslog(LOG_ERR, "Error fstat'ing config file (%s)", 
			strerror(errno));
		close(fd);
		return 1;
	}
	if (st.st_uid != 0) {
		syslog(LOG_ERR, "Error - %s isn't owned by root", 
			file);
		close(fd);
		return 1;
	}
	if ((st.st_mode & S_IWOTH) == S_IWOTH) {
		syslog(LOG_ERR, "Error - %s is world writable", 
			file);
		close(fd);
		return 1;
	}
	if (!S_ISREG(st.st_mode)) {
		syslog(LOG_ERR, "Error - %s is not a regular file", 
			file);
		close(fd);
		return 1;
	}

	/* it's ok, read line by line */
	f = fdopen(fd, "r");
	if (f == NULL) {
		syslog(LOG_ERR, "Error - fdopen failed (%s)", 
			strerror(errno));
		close(fd);
		return 1;
	}

	while (get_line(f, buf)) {
		// convert line into name-value pair
		const struct kw_pair *kw;
		struct nv_pair nv;
		rc = nv_split(buf, &nv);
		switch (rc) {
			case 0: // fine
				break;
			case 1: // not the right number of tokens.
				syslog(LOG_ERR, 
				"Wrong number of arguments for line %d in %s", 
					lineno, file);
				break;
			case 2: // no '=' sign
				syslog(LOG_ERR, 
					"Missing equal sign for line %d in %s", 
					lineno, file);
				break;
			default: // something else went wrong... 
				syslog(LOG_ERR, 
					"Unknown error for line %d in %s", 
					lineno, file);
				break;
		}
		if (nv.name == NULL) {
			lineno++;
			continue;
		}
		if (nv.value == NULL) {
			fclose(f);
			return 1;
		}

		/* identify keyword or error */
		kw = kw_lookup(nv.name);
		if (kw->name == NULL) {
			syslog(LOG_ERR, 
				"Unknown keyword \"%s\" in line %d of %s", 
				nv.name, lineno, file);
			fclose(f);
			return 1;
		}

		/* Check number of options */
		if (kw->max_options == 0 && nv.option != NULL) {
			syslog(LOG_ERR, 
				"Keyword \"%s\" has invalid option "
				"\"%s\" in line %d of %s", 
				nv.name, nv.option, lineno, file);
			fclose(f);
			return 1;
		}

		/* dispatch to keyword's local parser */
		rc = kw->parser(&nv, lineno, config);
		if (rc != 0) {
			fclose(f);
			return 1; // local parser puts message out
		}

		lineno++;
	}

	fclose(f);
	if (lineno > 1)
		return sanity_check(config, file);
	return 0;
}

static char *get_line(FILE *f, char *buf)
{
	if (fgets_unlocked(buf, 128, f)) {
		/* remove newline */
		char *ptr = strchr(buf, 0x0a);
		if (ptr)
			*ptr = 0;
		return buf;
	}
	return NULL;
}

static int nv_split(char *buf, struct nv_pair *nv)
{
	/* Get the name part */
	char *ptr;

	nv->name = NULL;
	nv->value = NULL;
	nv->option = NULL;
	ptr = strtok(buf, " ");
	if (ptr == NULL)
		return 0; /* If there's nothing, go to next line */
	if (ptr[0] == '#')
		return 0; /* If there's a comment, go to next line */
	nv->name = ptr;

	/* Check for a '=' */
	ptr = strtok(NULL, " ");
	if (ptr == NULL)
		return 1;
	if (strcmp(ptr, "=") != 0)
		return 2;

	/* get the value */
	ptr = strtok(NULL, " ");
	if (ptr == NULL)
		return 1;
	nv->value = ptr;

	/* See if there's an option */
	ptr = strtok(NULL, " ");
	if (ptr) {
		nv->option = ptr;

		/* Make sure there's nothing else */
		ptr = strtok(NULL, " ");
		if (ptr)
			return 1;
	}

	/* Everything is OK */
	return 0;
}

static const struct kw_pair *kw_lookup(const char *val)
{
	int i = 0;
	while (keywords[i].name != NULL) {
		if (strcasecmp(keywords[i].name, val) == 0)
			break;
		i++;
	}
	return &keywords[i];
}

static int check_exe_name(const char *val)
{
	struct stat buf;

	if (*val != '/') {
		syslog(LOG_ERR, "Absolute path needed for %s", val);
		return -1;
	}

	if (stat(val, &buf) < 0) {
		syslog(LOG_ERR, "Unable to stat %s (%s)", val,
			strerror(errno));
		return -1;
	}
	if (!S_ISREG(buf.st_mode)) {
		syslog(LOG_ERR, "%s is not a regular file", val);
		return -1;
	}
	if (buf.st_uid != 0) {
		syslog(LOG_ERR, "%s is not owned by root", val);
		return -1;
	}
	if ((buf.st_mode & (S_IRWXU|S_IRWXG|S_IWOTH)) !=
			   (S_IRWXU|S_IRGRP|S_IXGRP)) {
		syslog(LOG_ERR, "%s permissions should be 0750", val);
		return -1;
	}
	return 0;
}
 
static int server_parser(struct nv_pair *nv, int line, 
		remote_conf_t *config)
{
	if (nv->value)
		config->remote_server = strdup(nv->value);
	else
		config->remote_server = NULL;
	return 0;
}

static int port_parser(struct nv_pair *nv, int line, remote_conf_t *config)
{
	const char *ptr = nv->value;
	int i;

	/* check that all chars are numbers */
	for (i=0; ptr[i]; i++) {
		if (!isdigit(ptr[i])) {
			syslog(LOG_ERR,
				"Value %s should only be numbers - line %d",
				nv->value, line);
			return 1;
		}
	}

	/* convert to unsigned int */
	errno = 0;
	i = strtoul(nv->value, NULL, 10);
	if (errno) {
		syslog(LOG_ERR,
			"Error converting string to a number (%s) - line %d",
			strerror(errno), line);
		return 1;
	}
	/* Check its range */
	if (i > INT_MAX) {
		syslog(LOG_ERR,
			"Error - converted number (%s) is too large - line %d",
			nv->value, line);
		return 1;
	}
	config->port = (unsigned int)i;
	return 0;
}

static int transport_parser(struct nv_pair *nv, int line, remote_conf_t *config)
{
	int i;
	for (i=0; transport_words[i].name != NULL; i++) {
		if (strcasecmp(nv->value, transport_words[i].name) == 0) {
			config->mode = transport_words[i].option;
			return 0;
		}
	}
	syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
	return 1;
}

static int mode_parser(struct nv_pair *nv, int line, remote_conf_t *config)
{
	int i;
	for (i=0; mode_words[i].name != NULL; i++) {
		if (strcasecmp(nv->value, mode_words[i].name) == 0) {
			config->mode = mode_words[i].option;
			return 0;
		}
	}
	syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
	return 1;
}

static int depth_parser(struct nv_pair *nv, int line,
	remote_conf_t *config)
{
	const char *ptr = nv->value;
	int i;

	/* check that all chars are numbers */
	for (i=0; ptr[i]; i++) {
		if (!isdigit(ptr[i])) {
			syslog(LOG_ERR,
				"Value %s should only be numbers - line %d",
				nv->value, line);
			return 1;
		}
	}

	/* convert to unsigned int */
	errno = 0;
	i = strtoul(nv->value, NULL, 10);
	if (errno) {
		syslog(LOG_ERR,
			"Error converting string to a number (%s) - line %d",
			strerror(errno), line);
		return 1;
	}
	/* Check its range */
	if (i > INT_MAX) {
		syslog(LOG_ERR,
			"Error - converted number (%s) is too large - line %d",
			nv->value, line);
		return 1;
	}
	config->queue_depth = (unsigned int)i;
	return 0;
}

static int fail_action_parser(struct nv_pair *nv, int line,
	remote_conf_t *config)
{
	int i;
	for (i=0; fail_action_words[i].name != NULL; i++) {
		if (strcasecmp(nv->value, fail_action_words[i].name) == 0) {
			config->fail_action = fail_action_words[i].option;
			return 0;
		} else if (i == F_EXEC) {
			if (strncasecmp(fail_action_words[i].name,
							nv->value, 4) == 0){
				if (check_exe_name(nv->option))
					return 1;
				config->fail_exe = strdup(nv->option);
				config->fail_action = F_EXEC;
				return 0;
			}
		}
	}
	syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
 	return 1;
}

/*
 * This function is where we do the integrated check of the audispd config
 * options. At this point, all fields have been read. Returns 0 if no
 * problems and 1 if problems detected.
 */
static int sanity_check(remote_conf_t *config, const char *file)
{
	/* Error checking */
// server should have string
// port should be less that 32k
// queue_depth should be less than 100k
// If fail_action is F_EXEC, fail_exec must exist
	return 0;
}

void free_config(remote_conf_t *config)
{
	free((void *)config->remote_server);
}

