/* auparse.c --
 * Copyright 2006-07 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *      Steve Grubb <sgrubb@redhat.com>
 */

#include "config.h"
#include "internal.h"
#include "auparse.h"
#include "interpret.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


static int setup_log_file_array(auparse_state_t *au)
{
        struct daemon_conf config;
        char *filename, **tmp;
        int len, num = 0, i = 0;

        /* Load config so we know where logs are */
	set_aumessage_mode(MSG_STDERR, DBG_NO);
        load_config(&config, TEST_SEARCH);

        /* for each file */
        len = strlen(config.log_file) + 16;
        filename = malloc(len);
        if (!filename) {
                fprintf(stderr, "No memory\n");
                free_config(&config);
                return 1;
        }
        /* Find oldest log file */
        snprintf(filename, len, "%s", config.log_file);
        do {
                if (access(filename, R_OK) != 0)
                        break;
                num++;
                snprintf(filename, len, "%s.%d", config.log_file, num);
        } while (1);
        num--;
	tmp = malloc((num+2)*sizeof(char *));


        /* Got it, now process logs from last to first */
        if (num > 0)
                snprintf(filename, len, "%s.%d", config.log_file, num);
        else
                snprintf(filename, len, "%s", config.log_file);
        do {
		tmp[i++] = strdup(filename);

                /* Get next log file */
                num--;
                if (num > 0)
                        snprintf(filename, len, "%s.%d", config.log_file, num);
                else if (num == 0)
                        snprintf(filename, len, "%s", config.log_file);
                else
                        break;
        } while (1);

	// Terminate the list
	tmp[i] = NULL; 
	au->source_list = tmp;
	return 0;
}

/* General functions that affect operation of the library */
auparse_state_t *auparse_init(ausource_t source, const void *b)
{
	char **tmp, **bb = (char **)b;
	int n, i;

	auparse_state_t *au = malloc(sizeof(auparse_state_t));
	if (au == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	au->in = NULL;
	au->source_list = NULL;
	switch (source)
	{
		case AUSOURCE_LOGS:
			if (geteuid()) {
				errno = EPERM;
				goto bad_exit;
			}
			setup_log_file_array(au);
			break;
		case AUSOURCE_FILE:
			if (access(b, R_OK))
				goto bad_exit;
			tmp = malloc(2*sizeof(char *));
			tmp[0] = strdup(b);
			tmp[1] = NULL;
			au->source_list = tmp;
			break;
		case AUSOURCE_FILE_ARRAY:
			n = 0;
			while (bb[n]) {
				if (access(bb[n], R_OK))
					goto bad_exit;
				n++;
			}
			tmp = malloc((n+1)*sizeof(char *));
			for (i=0; i<n; i++)
				tmp[i] = strdup(bb[i]);
			tmp[n] = NULL;
			au->source_list = tmp;
			break;
		case AUSOURCE_BUFFER:
			tmp = malloc(2*sizeof(char *));
			tmp[0] = strdup(b);
			tmp[1] = NULL;
			au->source_list = tmp;
			break;
		case AUSOURCE_BUFFER_ARRAY:
			n = 0;
			while (bb[n])
				n++;
			tmp = malloc((n+1)*sizeof(char *));
			for (i=0; i<n; i++)
				tmp[i] = strdup(bb[i]);
			tmp[n] = NULL;
			au->source_list = tmp;
			break;
		case AUSOURCE_DESCRIPTOR:
			n = (long)b;
			au->in = fdopen(n, "r");
			break;
		case AUSOURCE_FILE_POINTER:
			au->in = (FILE *)b;
			break;
		default:
			errno = EINVAL;
			return NULL;
			break;
	}
	au->source = source;
	au->list_idx = 0;
	au->next_buf = NULL;
	au->off = 0;
	au->cur_buf = NULL;
	au->saved_buf = NULL;
	aup_list_create(&au->le);
	aurule_create(&au->rules);
	au->find_field = NULL;
	au->search_where = AUSEARCH_STOP_EVENT;
	au->search_how = AUSEARCH_RULE_CLEAR;

	return au;
bad_exit:
	free(au);
	return NULL;
}


int auparse_reset(auparse_state_t *au)
{
	if (au == NULL) {
		errno = EINVAL;
		return -1;
	}

	switch (au->source)
	{
		case AUSOURCE_LOGS:
		case AUSOURCE_FILE:
		case AUSOURCE_FILE_ARRAY:
			if (au->in) {
				fclose(au->in);
				au->in = NULL;
			}
		/* Fall through */
		case AUSOURCE_DESCRIPTOR:
		case AUSOURCE_FILE_POINTER:
			if (au->in) 
				rewind(au->in);
		/* Fall through */
		case AUSOURCE_BUFFER:
		case AUSOURCE_BUFFER_ARRAY:
			au->list_idx = 0;
			au->off = 0;
			break;
	}
	return 0;
}


static struct nv_pair optab[] = {
	{AUSEARCH_EXISTS, "exists"},
	{AUSEARCH_EQUAL, "="},
	{AUSEARCH_NOT_EQUAL, "!="},
};
#define OP_NAMES (sizeof(optab)/sizeof(optab[0]))

static int lookup_op(const char *op)
{
        int i;

        for (i = 0; i < OP_NAMES; i++)
                if (strcmp(optab[i].name, op) == 0)
                        return optab[i].value;

        return -1;
}


int ausearch_add_item(auparse_state_t *au, const char *field, const char *op,
	const char *value, ausearch_rule_t how)
{
	aurulenode rn;
	int t_op = lookup_op(op);
	if (op < 0)
		goto err_out;

	// Make sure there's a field
	if (field == NULL)
		goto err_out;

	// Do not allow regex to get replaced this way
	if (au->search_how == AUSEARCH_RULE_REGEX)
		goto err_out;

	// Make sure how is within range
	if (how < AUSEARCH_RULE_CLEAR || how > AUSEARCH_RULE_AND)
		goto err_out;
	if (how == AUSEARCH_RULE_CLEAR) {
		aurule_clear(&au->rules);
	} else if (how != au->search_how && 
				au->search_how != AUSEARCH_RULE_CLEAR) {
		errno = EEXIST;
		return -1;
	}

	// All pre-checks are done, build a rule
	rn.search_op = t_op;
	if (t_op == AUSEARCH_EXISTS)
		rn.val = NULL;
	else {
		if (value == NULL)
			goto err_out;
		rn.val = strdup(value);
	}
	rn.field = strdup(field);
	aurule_append(&au->rules, &rn);
	au->search_how = how;

	return 0;
err_out:
	errno = EINVAL;
	return -1;
}

int ausearch_add_regex(auparse_state_t *au, const char *expr)
{
//	aurulenode rn;

	// Make sure there's an expression
	if (expr == NULL)
		goto err_out;

	if (au->search_how == AUSEARCH_RULE_REGEX)
		goto err_out;

	// FIXME: Need to do a parse or something to make sure the
	// expression is legal

/*	rn.field = strdup(expr);
	rn.search_op = AUSEARCH_UNSET;
	rn.val = NULL;
	aurule_append(&au->rules, &rn);

	au->search_how = how;
	return 0; */

err_out:
	errno = EINVAL;
	return -1;
}

int ausearch_set_stop(auparse_state_t *au, austop_t where)
{
	if (where < AUSEARCH_STOP_EVENT || where > AUSEARCH_STOP_FIELD) {
		errno = EINVAL;
		return -1;
	}

	au->search_where = where;
	return 0;
}

void ausearch_clear(auparse_state_t *au)
{
	aurule_clear(&au->rules);
	au->search_where = AUSEARCH_STOP_EVENT;
	au->search_how = AUSEARCH_RULE_CLEAR;
}

void auparse_destroy(auparse_state_t *au)
{
	if (au->source_list) {
		int n = 0;
		while (au->source_list[n]) 
			free(au->source_list[n++]);
		free(au->source_list);
		au->source_list = NULL;
	}
//	free(au->next_buf);
	au->next_buf = NULL;
        free(au->cur_buf);
	au->cur_buf = NULL;
        free(au->saved_buf);
        au->saved_buf = NULL;
	aup_list_clear(&au->le);
        free(au->find_field);
	au->find_field = NULL;
	ausearch_clear(au);

	aulookup_destroy_uid_list();
	aulookup_destroy_gid_list();
	if (au->in) {
		fclose(au->in);
		au->in = NULL;
	}
	free(au);
}

/* alloc a new buffer, cur_buf which contains a null terminated line
 * without a newline (note, this implies the line may be empty (strlen == 0)) if
 * successfully read a blank line (e.g. containing only a single newline).
 * cur_buf will have been newly allocated with malloc.
 * 
 * Returns < 0 on error, 0 if input is exhausted, and 1 if success.
 * 
 * Note: cur_buf will be freed the next time this routine is called if
 * cur_buf is not NULL, callers who retain a reference to the cur_buf
 * pointer will need to set cur_buf to NULL to cause the previous cur_buf
 * allocation to persist.*/

static int readline_file(auparse_state_t *au)
{
	ssize_t rc;
	char *p_last_char;
	size_t n = 0;

	if (au->cur_buf != NULL) {
		free(au->cur_buf);
		au->cur_buf = NULL;
	}
	if (au->in == NULL) {
		errno = EBADF;
		return -1;
	}
	if ((rc = getline(&au->cur_buf, &n, au->in)) <= 0) {
		if (rc < 0 && !feof(au->in)) return -1;
		return 0;
	}
	p_last_char = au->cur_buf + (rc-1);
	if (*p_last_char == '\n') {	/* nuke newline */
		*p_last_char = 0;
	}
	return 1;
}


/* malloc & copy a line into cur_buf from the internal buffer,
 * next_buf.  cur_buf will contain a null terminated line without a
 * newline (note, this implies the line may be empty (strlen == 0)) if
 * successfully read a blank line (e.g. containing only a single
 * newline).
 * 
 * Returns < 0 on error, 0 if input is exhausted, and 1 if success.
 * 
 * Note: cur_buf will be freed the next time this routine is called if
 * cur_buf is not NULL, callers who retain a reference to the cur_buf
 * pointer will need to set cur_buf to NULL to cause the previous cur_buf
 * allocation to persist.*/
 
static int readline_buf(auparse_state_t *au)
{
	char *ptr,*new_ptr=NULL;

	if (au->cur_buf != NULL) {
		free(au->cur_buf);
		au->cur_buf = NULL;
	}

	ptr = au->next_buf + au->off;
	if (*ptr == 0)
		return 0;

	new_ptr = strchr(ptr, '\n');
	if (new_ptr) {
		// found a line dup it
		char tmp = *new_ptr;
		*new_ptr = 0;
		au->cur_buf = strdup(ptr);
		*new_ptr = tmp;
		au->off += strlen(au->cur_buf)+1;
		return 1;
	} else if (*ptr) {
		// there is text but no new line
		au->cur_buf = strdup(ptr);
		au->off += strlen(au->cur_buf);
		return 1;
	}
	
	return 0;
}

static int str2event(char *s, au_event_t *e)
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

static void extract_timestamp(const char *b, au_event_t *e)
{
	char *ptr, *tmp;

	tmp = strndupa(b, 80);
	ptr = strtok(tmp, " ");
	if (ptr) {
		// at this point we have type=
		ptr = strtok(NULL, " ");
		if (ptr) {
			if (*(ptr+9) == '(')
				ptr+=9;
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
//					audit_msg(LOG_ERROR,
//					  "Error extracting time stamp (%s)\n",
//						ptr);
				}
			}
			// else we have a bad line
		}
		// else we have a bad line
	}
	// else we have a bad line
}

static int events_are_equal(au_event_t *e1, au_event_t *e2)
{
	if (e1->serial == e2->serial && e1->milli == e2->milli &&
			e1->sec == e2->sec)
		return 1;
	else
		return 0;
}

/* This function will figure out how to get the next line of input.
 * storing it cur_buf. cur_buf will be NULL terminated but will not
 * contain a trailing newline. This implies a successful read 
 * (result == 1) may result in a zero length cur_buf if a blank line
 * was read.
 *
 * cur_buf will have been allocated with malloc. The next time this
 * routine is called if cur_buf is non-NULL cur_buf will be freed,
 * thus if the caller wishes to retain a reference to malloc'ed
 * cur_buf data it should copy the cur_buf pointer and set cur_buf to
 * NULL.
 *
 * Returns < 0 on error, 0 if input is exhausted, and 1 if success. */

static int retrieve_next_line(auparse_state_t *au)
{
	int rc;

	switch (au->source)
	{
		case AUSOURCE_DESCRIPTOR:
		case AUSOURCE_FILE_POINTER:
			return 0;
		case AUSOURCE_LOGS:
		case AUSOURCE_FILE:
		case AUSOURCE_FILE_ARRAY:
			// if the first time through, open file
			if (au->list_idx == 0 && au->in == NULL) {
				au->in = fopen(au->source_list[au->list_idx], "r");
				if (au->in == NULL) return -1;
			}

			// loop reading lines from a file
			while (au->in) {
				// Get next buffer from file
				if ((rc = readline_file(au)) > 0) return 1;
				if (rc < 0) return -1;
				// end of file, open next file, try readline again
				fclose(au->in);
				au->in = NULL;
				au->list_idx++;
				if (au->source_list[au->list_idx]) {
					au->in = fopen(au->source_list[au->list_idx], "r");
					if (au->in == NULL) return -1;
				}
			}
			return 0;
		case AUSOURCE_BUFFER:
		case AUSOURCE_BUFFER_ARRAY:
			if (au->list_idx == 0 && au->next_buf == NULL)
				au->next_buf = au->source_list[au->list_idx];

			while (au->next_buf) {
				if (readline_buf(au) > 0) return 1;
				// end of buffer, advance to next buffer, try readline again
				au->off = 0;
				au->list_idx++;
				au->next_buf = au->source_list[au->list_idx];
			}
			return 0;
		default:
			return -1;
	}
	return -1;		/* should never reach here */
}

/*******
* Functions that traverse events.
********/
static int ausearch_reposition_cursors(auparse_state_t *au)
{
	int rc = 0;

	switch (au->search_where)
	{
		case AUSEARCH_STOP_EVENT:
			aup_list_first(&au->le);
			aup_list_first_field(&au->le);
			break;
		case AUSEARCH_STOP_RECORD:
			aup_list_first_field(&au->le);
			break;
		case AUSEARCH_STOP_FIELD:
			// do nothing - this is the normal stopping point
			break;
		default:
			rc = -1;
			break;
	}
	return rc;
}

/* This is called during search once per each record. It walks the list
 * of nvpairs and decides if a field matches. */
static int ausearch_compare(auparse_state_t *au)
{
	rnode *r;

	if (au->search_how == AUSEARCH_RULE_REGEX) {
		// FIXME: need to code this one
		errno = ENOSYS;
		return -1;
	}
	r = aup_list_get_cur(&au->le);
	if (r) {
		// for each rule item
		int results = (au->search_how == AUSEARCH_RULE_AND);
		aurule_first(&au->rules);
		do {
			int rc, tmp = 0;

			aurulenode *rule = aurule_get_cur(&au->rules);
			if (rule == NULL) 
				continue;
			rc = nvlist_find_name(&r->nv, rule->field);
			if (rc) {
				if (rule->search_op == AUSEARCH_EXISTS)
					return 1;
				rc = strcmp(rule->val,
					    nvlist_get_cur_val(&r->nv));
				if (rule->search_op == AUSEARCH_EQUAL)
					tmp = (rc == 0);
				else
					tmp = (rc != 0);
			}
			if (au->search_how == AUSEARCH_RULE_AND) {
				if (tmp == 0)
					return 0; /* all must match */
			} else if (au->search_how <= AUSEARCH_RULE_OR && tmp)
				return 1; /* Anytime tmp == 1 short circuit */
		} while (aurule_next(&au->rules));
		if (results)
			return 1;
	}
	
	return 0;
}

// Returns < 0 on error, 0 no data, > 0 success
int ausearch_next_event(auparse_state_t *au)
{
	int rc;

	if (au->rules.cnt == 0) {
		errno = EINVAL;
		return -1;
	}
	if ((rc = auparse_first_record(au)) <= 0)
		return rc;
        do {
		do {
			if ((rc = ausearch_compare(au)) > 0) {
				ausearch_reposition_cursors(au);
				return 1;
			} else if (rc < 0)
				return rc;
               	} while ((rc = auparse_next_record(au)) > 0);
		if (rc < 0)
			return rc;
        } while ((rc = auparse_next_event(au)) > 0);
	if (rc < 0)
		return rc;
	
	return 0;
}

// Brute force go to next event. Returns < 0 on error, 0 no data, > 0 success
int auparse_next_event(auparse_state_t *au)
{
	int rc;

	if (au == NULL)
		return -1;

	// Tear down old event info
	aup_list_clear(&au->le);

	// Get the next line
	if (au->saved_buf) {
		au->cur_buf = au->saved_buf;
		au->saved_buf = NULL;
	} else {
		rc = retrieve_next_line(au);
		if (rc <= 0)
			return rc;	// Error or empty
	}

	do {
		au_event_t e;

		extract_timestamp(au->cur_buf, &e);
		if (au->le.cnt == 0)
			aup_list_set_event(&au->le, &e);

		if (events_are_equal(&au->le.e, &e)) {
			// If they are equal, add this to the event
			aup_list_append(&au->le, &e, au->cur_buf);

			// The list took custody of the line so empty pointer
			au->cur_buf = NULL;

			rc = retrieve_next_line(au);
			if (rc < 0)
				return rc;	// Error stop
			else if (rc == 0) 
				goto reset_current; // Consumed all data
		} else {
			// Events are not equal...stop...emit event
 			au->saved_buf = au->cur_buf;
 			au->cur_buf = NULL;
			goto reset_current;
 		}
	} while (1);

reset_current:
	// Set cursor to first record of new event
	aup_list_first(&au->le);
	// Set field cursor to 1st field of cur record
	aup_list_first_field(&au->le);
	if (aup_list_get_cnt(&au->le))
		return 1;
	else
		return 0;
}


/* Accessors to event data */
const au_event_t *auparse_get_timestamp(auparse_state_t *au)
{
	if (au && au->le.e.sec != 0)
		return &au->le.e;
	else
		return NULL;
}


time_t auparse_get_time(auparse_state_t *au)
{
	if (au)
		return au->le.e.sec;
	else
		return 0;
}


unsigned int auparse_get_milli(auparse_state_t *au)
{
	if (au)
		return au->le.e.milli;
	else
		return 0;
}


unsigned long auparse_get_serial(auparse_state_t *au)
{
	if (au)
		return au->le.e.serial;
	else
		return 0;
}


// Gets the machine node name
const char *auparse_get_node(auparse_state_t *au)
{
// FIXME Need to do this one
	return NULL;
}


int auparse_timestamp_compare(au_event_t *e1, au_event_t *e2)
{
	if (e1->sec > e2->sec)
		return 1;
	if (e1->sec < e2->sec)
		return -1;

	if (e1->milli > e2->milli)
		return 1;
	if (e1->milli < e2->milli)
		return -1;

	if (e1->serial > e2->serial)
		return 1;
	if (e1->serial < e2->serial)
		return -1;

	return 0;
}

unsigned int auparse_get_num_records(auparse_state_t *au)
{
	return aup_list_get_cnt(&au->le);
}


/* Functions that traverse records in the same event */
int auparse_first_record(auparse_state_t *au)
{
	int rc;

	if (aup_list_get_cnt(&au->le) == 0) {
		rc = auparse_next_event(au);
		if (rc <= 0)
			return rc;
	}
	aup_list_first(&au->le);
	
	return 1;
}


int auparse_next_record(auparse_state_t *au)
{
	if (aup_list_get_cnt(&au->le) == 0) { 
		int rc = auparse_first_record(au);
		if (rc <= 0)
			return rc;
	}
	if (aup_list_next(&au->le))
		return 1;
	else
		return 0;
}


/* Accessors to record data */
int auparse_get_type(auparse_state_t *au)
{
	rnode *r = aup_list_get_cur(&au->le);
	if (r) 
		return r->type;
	else
		return 0;
}


int auparse_first_field(auparse_state_t *au)
{
	return aup_list_first_field(&au->le);
}


int auparse_next_field(auparse_state_t *au)
{
	rnode *r = aup_list_get_cur(&au->le);
	if (r) {
		if (nvlist_next(&r->nv))
			return 1;
		else
			return 0;
	}
	return 0;
}


unsigned int auparse_get_num_fields(auparse_state_t *au)
{
	rnode *r = aup_list_get_cur(&au->le);
	if (r)
		return nvlist_get_cnt(&r->nv);
	else
		return 0;
}

const char *auparse_get_record_text(auparse_state_t *au)
{
	rnode *r = aup_list_get_cur(&au->le);
	if (r) 
		return r->record;
	else
		return NULL;
}


/* scan from current location to end of event */
const char *auparse_find_field(auparse_state_t *au, const char *name)
{
	free(au->find_field);
	au->find_field = strdup(name);
	return auparse_find_field_next(au);
}

const char *auparse_find_field_next(auparse_state_t *au)
{
	if (au->find_field == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if (au->le.e.sec) {
		rnode *r = aup_list_get_cur(&au->le);
		while (r) {
			do {
				int rc = nvlist_find_name(&r->nv,
							au->find_field);
				if (rc) 
					return nvlist_get_cur_val(&r->nv);
			} while (nvlist_next(&r->nv));
			r = aup_list_next(&au->le);
		}
	}
	return NULL;
}


/* Accessors to field data */
const char *auparse_get_field_name(auparse_state_t *au)
{
	if (au->le.e.sec) {
		rnode *r = aup_list_get_cur(&au->le);
		if (r) 
			return nvlist_get_cur_name(&r->nv);
	}
	return NULL;
}


const char *auparse_get_field_str(auparse_state_t *au)
{
	if (au->le.e.sec) {
		rnode *r = aup_list_get_cur(&au->le);
		if (r) 
			return nvlist_get_cur_val(&r->nv);
	}
	return NULL;
}


int auparse_get_field_int(auparse_state_t *au)
{
	const char *v = auparse_get_field_str(au);
	if (v) {
		int val;

		errno = 0;
		val = strtol(v, NULL, 10);
		if (errno == 0)
			return val;
	} else
		errno = ENODATA;
	return -1;
}


const char *auparse_interpret_field(auparse_state_t *au)
{
        if (au->le.e.sec) {
                rnode *r = aup_list_get_cur(&au->le);
                if (r)
                        return nvlist_interp_cur_val(r);
        }
	return NULL;
}

