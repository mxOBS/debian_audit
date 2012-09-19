/*
* ellist.h - Header file for ellist.c
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

#ifndef ELLIST_HEADER
#define ELLIST_HEADER

#include "config.h"
#include "private.h"
#include "auparse-defs.h"
#include <sys/types.h>
#include "nvlist.h"

/* This is the linked list head. Only data elements that are 1 per
 * event goes here. */
typedef struct {
	rnode *head;		// List head
	rnode *cur;		// Pointer to current node
	unsigned int cnt;	// How many items in this list

	// Data we add as 1 per event
	au_event_t e;		// event - time & serial number
} event_list_t;

void aup_list_create(event_list_t *l);
void aup_list_clear(event_list_t* l);
static inline unsigned int aup_list_get_cnt(event_list_t *l) { return l->cnt; }
static inline void aup_list_first(event_list_t *l) { l->cur = l->head; }
static inline rnode *aup_list_get_cur(event_list_t *l) { return l->cur; }
rnode *aup_list_next(event_list_t *l);
int aup_list_append(event_list_t *l, au_event_t *e, char *message);
int aup_list_get_event(event_list_t* l, au_event_t *e);
int aup_list_set_event(event_list_t* l, au_event_t *e);

/* Given a message type, find the matching node */
rnode *aup_list_find_rec(event_list_t *l, int i);

/* Given two message types, find the first matching node */
rnode *aup_list_find_rec_range(event_list_t *l, int low, int high);

int aup_list_first_field(event_list_t *l);

/* Make these hidden to prevent conflicts */
hidden_proto(aup_list_create);
hidden_proto(aup_list_clear);
hidden_proto(aup_list_get_cnt);
hidden_proto(aup_list_first);
hidden_proto(aup_list_get_cur);
hidden_proto(aup_list_next);
hidden_proto(aup_list_append);
hidden_proto(aup_list_set_event);
hidden_proto(aup_list_first_field);
// not fully exposed, but we them here
hidden_proto(aup_list_get_event);
hidden_proto(aup_list_find_rec);
hidden_proto(aup_list_find_rec_range);

#endif

