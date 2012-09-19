/*
* ausearch-llist.h - Header file for ausearch-llist.c
* Copyright (c) 2005-2006 Red Hat Inc., Durham, North Carolina.
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

#ifndef AULIST_HEADER
#define AULIST_HEADER

#include "config.h"
#include <sys/types.h>
#include "ausearch-string.h"
#include "ausearch-avc.h"
#include "ausearch-common.h"


typedef struct
{
        time_t sec;		// Event seconds
        unsigned int milli;	// millisecond of the timestamp
        unsigned long serial;	// Serial number of the event
} event;

typedef struct
{
  pid_t ppid;           // parent process ID
  pid_t pid;            // process ID
  uid_t uid;            // user ID
  uid_t euid;           // effective user ID
  uid_t loginuid;       // login user ID
  gid_t gid;            // group ID
  gid_t egid;           // effective group ID
  success_t success;    // success flag, 1 = yes, 0 = no, -1 = unset
  int arch;             // arch
  int syscall;          // syscall
  char *hostname;       // hostname
  slist *filename;      // filename list
  char *cwd;            // current working dir
  char *exe;            // executable
  char *key;            // key field
  char *terminal;       // terminal
  char *comm;           // comm name
  alist *avc;		// avcs for the event
  char *acct;		// account used when uid is invalid
} search_items;

/* This is the node of the linked list. message & item are the only elements
 * at this time. Any data elements that are per item goes here. */
typedef struct _lnode{
  char *message;	// The whole unparsed message
  int type;             // message type (KERNEL, USER, LOGIN, etc)
  unsigned long long a0;	// argv 0
  unsigned int item;	// Which item of the same event
  struct _lnode* next;	// Next node pointer
} lnode;

/* This is the linked list head. Only data elements that are 1 per
 * event goes here. */
typedef struct {
  lnode *head;		// List head
  lnode *cur;		// Pointer to current node
  unsigned int cnt;	// How many items in this list

			// Data we add as 1 per event
  event e;		// event - time & serial number
  search_items s;	// items in master rec that are searchable
} llist;

void list_create(llist *l);
static inline void list_first(llist *l) { l->cur = l->head; }
void list_last(llist *l);
lnode *list_next(llist *l);
lnode *list_prev(llist *l);
static inline lnode *list_get_cur(llist *l) { return l->cur; }
void list_append(llist *l, lnode *node);
void list_clear(llist* l);
int list_get_event(llist* l, event *e);

/* Given a numeric index, find that record. */
int list_find_item(llist *l, unsigned int i);

/* Given a message type, find the matching node */
lnode *list_find_msg(llist *l, int i);

/* Given two message types, find the first matching node */
lnode *list_find_msg_range(llist *l, int low, int high);

#endif

