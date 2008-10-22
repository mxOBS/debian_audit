/*
* ausearch-int.c - Minimal linked list library for integers
* Copyright (c) 2005,2008 Red Hat Inc., Durham, North Carolina.
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
#include <string.h>
#include "ausearch-int.h"

void ilist_create(ilist *l)
{
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

int_node *ilist_next(ilist *l)
{
	if (l->cur == NULL)
		return NULL;
	l->cur = l->cur->next;
	return l->cur;
}

void ilist_append(ilist *l, int num, unsigned int hits, int aux)
{
	int_node* newnode;

	newnode = malloc(sizeof(int_node));

	newnode->num = num;
	newnode->hits = hits;
	newnode->aux1 = aux;
	newnode->next = NULL;

	// if we are at top, fix this up
	if (l->head == NULL)
		l->head = newnode;
	else	// Otherwise add pointer to newnode
		l->cur->next = newnode;

	// make newnode current
	l->cur = newnode;
	l->cnt++;
}

void ilist_clear(ilist* l)
{
	int_node* nextnode;
	register int_node* current;

	if (l == NULL)
		return;

	current = l->head;
	while (current) {
		nextnode=current->next;
		free(current);
		current=nextnode;
	}
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

int ilist_add_if_uniq(ilist *l, int num, int aux)
{
	register int_node *cur, *prev;

	prev = cur = l->head;
	while (cur) {
		if (cur->num == num) {
			cur->hits++;
			return 0;
		} else if (num > cur->num) {
			prev = cur;
			cur = cur->next;
		} else {
			// Insert so list is from low to high
			if (prev == l->head)
				l->head = NULL;
			else
				l->cur = prev;
			ilist_append(l, num, 1, aux);
			l->cur->next = cur;
			return 1;
		}
	}

	/* No matches, append to the end */
	ilist_append(l, num, 1, aux);
	return 1;
}

void ilist_sort_by_hits(ilist *l)
{
	register int_node* cur, *prev = NULL;

	if (l->cnt <= 1)
		return;

	cur = l->head;

	/* Make sure l->cur points to end */
	if (l->cur->next != NULL) {
		prev = l->cur->next;
		while (prev->next)
			prev = prev->next;
		l->cur = prev;
	}

	while (cur && cur->next) {
		/* If the next node is bigger */
		if (cur->hits < cur->next->hits) {
			// detach node
			if (l->head == cur)
				l->head = cur->next;
			if (prev)
				prev->next = cur->next;
			else
				prev = cur->next;

			// append
			ilist_append(l, cur->num, cur->hits, cur->aux1);
			free(cur);

			// start over
			cur = l->head;
			prev = NULL;
			continue;
		}
		prev = cur;
		cur = cur->next;
	}
}

