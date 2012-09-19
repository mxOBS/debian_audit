/*
* ellist.c - Minimal linked list library
* Copyright (c) 2006-07 Red Hat Inc., Durham, North Carolina.
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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libaudit.h>
#include "ellist.h"

void aup_list_create(event_list_t *l)
{
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
	l->e.milli = 0L;       
	l->e.sec = 0L;         
	l->e.serial = 0L;
}
hidden_def(aup_list_create);

static void aup_list_last(event_list_t *l)
{
        register rnode* window;
	
	if (l->head == NULL)
		return;

        window = l->head;
	while (window->next)
		window = window->next;
	l->cur = window;
}

rnode *aup_list_next(event_list_t *l)
{
	if (l->cur)
		l->cur = l->cur->next;
	return l->cur;
}
hidden_def(aup_list_next);

/* This funtion does the heavy duty work of splitting a record into
 * its little tiny pieces */
static int parse_up_record(rnode* r)
{
	char *ptr, *buf, *saved;

	buf = strdup(r->record);
	ptr = strtok_r(buf, " ", &saved);
	if (ptr == NULL)
		return -1;

	do {	// If there's an '=' sign, its a keeper
		nvnode n;
		char *val = strchr(ptr, '=');
		if (val) {
			int len;

			// If name is 'msg=audit' throw it away
			if (*ptr == 'm' && strncmp(ptr, "msg=", 4) == 0) {
				if (ptr[4] == 'a')
					continue;

				// If name is 'msg='' chop off and see
				// if there is still a = in the string.
				else if (ptr[4] == '\'') {
					ptr += 5;
					val = strchr(ptr, '=');
					if (val == NULL)
						continue;
				}
			}

			// Split the string
			*val = 0;
			val++;

			// Remove beginning cruft of name
			if (*ptr == '(')
				ptr++;
			n.name = strdup(ptr);
			n.val = strdup(val);
			// Remove trailing punctuation
			len = strlen(n.val);
			if (len && n.val[len-1] == ':') {
				n.val[len-1] = 0;
				len--;
			}
			if (len && n.val[len-1] == ',') {
				n.val[len-1] = 0;
				len--;
			}
			if (len && n.val[len-1] == '\'') {
				n.val[len-1] = 0;
				len--;
			}
			if (len && n.val[len-1] == ')') {
				if (strcmp(n.val, "(none)") &&
					strcmp(n.val, "(null)")) {
					n.val[len-1] = 0;
					len--;
				}
			}
			nvlist_append(&r->nv, &n);
			if (r->nv.cnt == 1 && strcmp(n.name, "type") == 0) {
				r->type = audit_name_to_msg_type(n.val);
			} else if(r->nv.cnt == 2 && strcmp(n.name, "arch")== 0){
				unsigned int ival;
				errno = 0;
				ival = strtoul(n.val, NULL, 16);
				if (errno)
					r->machine = -1;
				r->machine = audit_elf_to_machine(ival);
			} else if(r->nv.cnt == 3 && strcmp(n.name,
							"syscall") == 0){
				errno = 0;
				r->syscall = strtoul(n.val, NULL, 10);
				if (errno)
					r->syscall = -1;
			} else if(r->nv.cnt == 6 && strcmp(n.name, "a0") == 0){
				errno = 0;
				r->a0 = strtoull(n.val, NULL, 16);
				if (errno)
					r->a0 = -1LL;
			} else if(r->nv.cnt == 7 && strcmp(n.name, "a1") == 0){
				errno = 0;
				r->a1 = strtoull(n.val, NULL, 16);
				if (errno)
					r->a1 = -1LL;
			}
		} else if (r->type == AUDIT_AVC || r->type == AUDIT_USER_AVC) {
			// We special case these 2 fields because selinux
			// avc messages do not label these fields.
			if (nvlist_get_cnt(&r->nv) == 1) {
				// skip over 'avc:'
				if (strncmp(ptr, "avc", 3) == 0)
					continue;
				n.name = strdup("seresults");
			} else if (nvlist_get_cnt(&r->nv) == 2) {
				// skip over open brace
				if (*ptr == '{') {
					int total = 0, len;
					char tmpctx[256], *to;
					tmpctx[0] = 0;
					to = tmpctx;
					ptr = strtok_r(NULL, " ", &saved);
					while (ptr && *ptr != '}') {
						len = strlen(ptr);
						if ((len+1) >= (256-total))
							return -1;
						if (tmpctx[0]) {
							to = stpcpy(to, ",");
							total++;
						}
						to = stpcpy(to, ptr);
						total += len;
						ptr = strtok_r(NULL, " ",
								 &saved);
					}
					n.name = strdup("seperms");
					n.val = strdup(tmpctx);
					nvlist_append(&r->nv, &n);
					continue;
				}
			} else
				continue;
			n.val = strdup(ptr);
			nvlist_append(&r->nv, &n);
		}
		// FIXME: There should be an else here to catch ancillary data
	} while((ptr = strtok_r(NULL, " ", &saved)));

	free(buf);
	r->nv.cur = r->nv.head;	// reset to beginning
	return 0;
}

int aup_list_append(event_list_t *l, au_event_t *e, char *record)
{
	rnode* r;

	if (record == NULL)
		return -1;

	// First step is build rnode
	r = malloc(sizeof(rnode));
	if (r == NULL)
		return -1;

	r->record = record;
	r->type = 0;
	r->a0 = 0LL;
	r->a1 = 0LL;
	r->machine = -1;
	r->syscall = -1;
	r->item = l->cnt; 
	r->next = NULL;
	nvlist_create(&r->nv);

	// if we are at top, fix this up
	if (l->head == 0)
		l->head = r;
	else {	// Otherwise add pointer to newnode
		aup_list_last(l);
		l->cur->next = r;
	}

	// make newnode current
	l->cur = r;
	l->cnt++;

	// Then parse the record up into nvlist
	return parse_up_record(r);	
}
hidden_def(aup_list_append);

void aup_list_clear(event_list_t* l)
{
	rnode* nextnode;
	register rnode* current;

	if (l == NULL)
		return;

	current = l->head;
	while (current) {
		nextnode=current->next;
		nvlist_clear(&current->nv);
		free(current->record);
		free(current);
		current=nextnode;
	}
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
	l->e.milli = 0L;       
	l->e.sec = 0L;         
	l->e.serial = 0L;      
}
hidden_def(aup_list_clear);

int aup_list_get_event(event_list_t* l, au_event_t *e)
{
	if (l == NULL || e == NULL)
		return 0;

	e->sec = l->e.sec;
        e->milli = l->e.milli;
        e->serial = l->e.serial;
	return 1;
}
hidden_def(aup_list_get_event);

int aup_list_set_event(event_list_t* l, au_event_t *e)
{
	if (l == NULL || e == NULL)
		return 0;

	l->e.sec = e->sec;
        l->e.milli = e->milli;
        l->e.serial = e->serial;
	return 1;
}
hidden_def(aup_list_set_event);

rnode *aup_list_find_rec(event_list_t *l, int i)
{
        register rnode* window;
                                                                                
       	window = l->head;	/* start at the beginning */
	while (window) {
		if (window->type == i) {
			l->cur = window;
			return window;
		} else
			window = window->next;
	}
	return NULL;
}
hidden_def(aup_list_find_rec);

rnode *aup_list_find_rec_range(event_list_t *l, int low, int high)
{
        register rnode* window;

	if (high <= low)
		return NULL;

       	window = l->head;	/* Start at the beginning */
	while (window) {
		if (window->type >= low && window->type <= high) {
			l->cur = window;
			return window;
		} else
			window = window->next;
	}
	return NULL;
}
hidden_def(aup_list_find_rec_range);

int aup_list_first_field(event_list_t *l)
{
	if (l->cur) {
		nvlist_first(&l->cur->nv);
		return 1;
	} else
		return 0;
}
hidden_def(aup_list_first_field);

