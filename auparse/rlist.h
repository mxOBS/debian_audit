/*
* rlist.h - Header file for ausearch-aurule.c
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

#ifndef RLIST_HEADER
#define RLIST_HEADER

#include "config.h"
#include "private.h"
#include <auparse-defs.h>

/* This is the node of the linked list. Any data elements that are
 * per item goes here. */
typedef struct _aurulenode{
  char *field;			// The field name string
  ausearch_op_t search_op;	// What search op is being done
  char *val;			// The value field
  unsigned int item;		// Which item of the same event
  struct _aurulenode* next;	// Next aurule node pointer
} aurulenode;

/* This is the linked list head. Only data elements that are 1 per
 * event goes here. */
typedef struct {
  aurulenode *head;	// List head
  aurulenode *cur;	// Pointer to current node
  unsigned int cnt;	// How many items in this list
} aurule_list_t;

void aurule_create(aurule_list_t *l);
static inline void aurule_first(aurule_list_t *l) { l->cur = l->head; }
static inline aurulenode *aurule_get_cur(aurule_list_t *l) { return l->cur; }
void aurule_append(aurule_list_t *l, aurulenode *node);
void aurule_clear(aurule_list_t *l);
aurulenode *aurule_next(aurule_list_t *l);

/* Make these hidden to prevent conflicts */
hidden_proto(aurule_create);
hidden_proto(aurule_first);
hidden_proto(aurule_get_cur);
hidden_proto(aurule_append);
hidden_proto(aurule_clear);
hidden_proto(aurule_next);

#endif

