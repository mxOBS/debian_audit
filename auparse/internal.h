/* internal.h -- 
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
 *	Steve Grubb <sgrubb@redhat.com>
 */
#ifndef AUPARSE_INTERNAL_HEADER_
#define AUPARSE_INTERNAL_HEADER

#include "auparse-defs.h"
#include "ellist.h"
#include "rlist.h"
#include "auditd-config.h"
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Some prototypes to remove functions from public api */
#ifdef PIC
# define hidden __attribute__ ((visibility ("hidden")))
# define hidden_proto(fct) __hidden_proto (fct, fct##_internal)
# define __hidden_proto(fct, internal)  \
     extern __typeof (fct) internal;    \
     extern __typeof (fct) fct __asm (#internal) hidden;
# if defined(__alpha__) || defined(__mips__)
#  define hidden_def(fct) \
     asm (".globl " #fct "\n" #fct " = " #fct "_internal");
# else
#  define hidden_def(fct) \
     asm (".globl " #fct "\n.set " #fct ", " #fct "_internal");
#endif
#else
# define hidden
# define hidden_proto(fct)
# define hidden_def(fct)
#endif

/* This is the name/value pair used by search tables */
struct nv_pair {
	int        value;
	const char *name;
};

typedef struct opaque
{
	ausource_t source;	// Source type
	char **source_list;	// Array of buffers, or array of file names
	int list_idx;		// The index into the source list
	FILE *in;		// If source is file, this is the fd
	char *next_buf;		// The current buffer being broken down
	unsigned int off;	// The current offset into next_buf
	char *cur_buf;		// The current buffer being parsed
	char *saved_buf;	// The buffer saved for next line
	event_list_t le;	// Linked list of record in same event
	aurule_list_t rules;	// Search rules
	char *find_field;	// Used to store field name when searching
	austop_t search_where;	// Where to put the cursors on a match
	ausearch_rule_t search_how;	// How the rules are to be applied
}auparse_state_t;

// This is the main messaging function used internally
extern int audit_send_user_message(int fd, int type, const char *message);

// libaudit.c
hidden_proto(audit_send_user_message)

// auditd-config.c
hidden_proto(load_config)
hidden_proto(free_config)

// rlist.c
hidden_proto(aurule_next)


#ifdef __cplusplus
}
#endif

#endif

