/*
* rlist.c - Minimal linked list library for search rules
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
#include <stdlib.h>
#include "rlist.h"
#include "internal.h"


void aurule_create(aurule_list_t *l)
{
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}
hidden_def(aurule_create);

static void aurule_last(aurule_list_t *l)
{
        register aurulenode* window;
	
	if (l->head == NULL)
		return;

        window = l->head;
	while (window->next)
		window = window->next;
	l->cur = window;
}

void aurule_append(aurule_list_t *l, aurulenode *node)
{
	aurulenode* newnode = malloc(sizeof(aurulenode));

	newnode->field = node->field;
	newnode->search_op = node->search_op;
	newnode->val = node->val;
	newnode->item = l->cnt; 
	newnode->next = NULL;

	// if we are at top, fix this up
	if (l->head == NULL)
		l->head = newnode;
	else {	// Otherwise add pointer to newnode
		if (l->cnt == (l->cur->item+1)) {
			l->cur->next = newnode;
		}
		else {
			aurule_last(l);
			l->cur->next = newnode;
		}
	}

	// make newnode current
	l->cur = newnode;
	l->cnt++;
}
hidden_def(aurule_append);

void aurule_clear(aurule_list_t *l)
{
	aurulenode* nextnode;
	register aurulenode* current;

	current = l->head;
	while (current) {
		nextnode=current->next;
		free(current->field);
		free(current->val);
		free(current);
		current=nextnode;
	}
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}
hidden_def(aurule_clear);

aurulenode *aurule_next(aurule_list_t *l)
{
        if (l->cur)
        	l->cur = l->cur->next;
        return l->cur;
}
hidden_def(aurule_next);

