/* lookup_table.c -- 
 * Copyright 2004-2006 Red Hat Inc., Durham, North Carolina.
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
 *      Rickard E. (Rik) Faith <faith@redhat.com>
 */

#include "config.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "libaudit.h"
#include "private.h"

struct transtab {
    int   value;
    int   offset;
};

#define MSGSTRFIELD(line) MSGSTRFIELD1(line)
#define MSGSTRFIELD1(line) str##line

struct int_transtab {
    int        key;
    unsigned int  lvalue;
};

/* To create the following tables in a DSO-friendly way we split them in
   two separate variables: a long string which is created by concatenating
   all strings referenced in the table and the table itself, which uses
   offsets instead of string pointers.  To do this without increasing
   the maintenance burden we use a lot of preprocessor magic.  All the
   maintainer has to do is to add a new entry to the included file and
   recompile.  */

static const union i386_syscalltab_msgstr_t {
    struct {
#define _S(n, s) char MSGSTRFIELD(__LINE__)[sizeof (s)];
#include "i386_table.h"
#undef _S
    };
    char str[0];
} i386_syscalltab_msgstr = { {
#define _S(n, s) s,
#include "i386_table.h"
#undef _S
} };
static const struct transtab i386_syscalltab[] = {
#define _S(n, s) { n, offsetof(union i386_syscalltab_msgstr_t,	\
			       MSGSTRFIELD(__LINE__)) },
#include "i386_table.h"
#undef _S
};
#define AUDIT_I386_SYSCALL_NAMES (sizeof(i386_syscalltab)/sizeof(i386_syscalltab[0]))

static const union x86_64_syscalltab_msgstr_t {
    struct {
#define _S(n, s) char MSGSTRFIELD(__LINE__)[sizeof (s)];
#include "x86_64_table.h"
#undef _S
    };
    char str[0];
} x86_64_syscalltab_msgstr = { {
#define _S(n, s) s,
#include "x86_64_table.h"
#undef _S
} };
static const struct transtab x86_64_syscalltab[] = {
#define _S(n, s) { n, offsetof(union x86_64_syscalltab_msgstr_t,  \
                               MSGSTRFIELD(__LINE__)) },
#include "x86_64_table.h"
#undef _S
};
#define AUDIT_X86_64_SYSCALL_NAMES (sizeof(x86_64_syscalltab)/sizeof(x86_64_syscalltab[0]))

static const union ppc_syscalltab_msgstr_t {
    struct {
#define _S(n, s) char MSGSTRFIELD(__LINE__)[sizeof (s)];
#include "ppc_table.h"
#undef _S
    };
    char str[0];
} ppc_syscalltab_msgstr = { {
#define _S(n, s) s,
#include "ppc_table.h"
#undef _S
} };
static const struct transtab ppc_syscalltab[] = {
#define _S(n, s) { n, offsetof(union ppc_syscalltab_msgstr_t,  \
                               MSGSTRFIELD(__LINE__)) },
#include "ppc_table.h"
#undef _S
};
#define AUDIT_PPC_SYSCALL_NAMES (sizeof(ppc_syscalltab)/sizeof(ppc_syscalltab[0]))

static const union s390x_syscalltab_msgstr_t {
    struct {
#define _S(n, s) char MSGSTRFIELD(__LINE__)[sizeof (s)];
#include "s390x_table.h"
#undef _S
    };
    char str[0];
} s390x_syscalltab_msgstr = { {
#define _S(n, s) s,
#include "s390x_table.h"
#undef _S
} };
static const struct transtab s390x_syscalltab[] = {
#define _S(n, s) { n, offsetof(union s390x_syscalltab_msgstr_t,  \
                               MSGSTRFIELD(__LINE__)) },
#include "s390x_table.h"
#undef _S
};
#define AUDIT_S390X_SYSCALL_NAMES (sizeof(s390x_syscalltab)/sizeof(s390x_syscalltab[0]))

static const union s390_syscalltab_msgstr_t {
    struct {
#define _S(n, s) char MSGSTRFIELD(__LINE__)[sizeof (s)];
#include "s390_table.h"
#undef _S
    };
    char str[0];
} s390_syscalltab_msgstr = { {
#define _S(n, s) s,
#include "s390_table.h"
#undef _S
} };
static const struct transtab s390_syscalltab[] = {
#define _S(n, s) { n, offsetof(union s390_syscalltab_msgstr_t,  \
                               MSGSTRFIELD(__LINE__)) },
#include "s390_table.h"
#undef _S
};
#define AUDIT_S390_SYSCALL_NAMES (sizeof(s390_syscalltab)/sizeof(s390_syscalltab[0]))

static const union ia64_syscalltab_msgstr_t {
    struct {
#define _S(n, s) char MSGSTRFIELD(__LINE__)[sizeof (s)];
#include "ia64_table.h"
#undef _S
    };
    char str[0];
} ia64_syscalltab_msgstr = { {
#define _S(n, s) s,
#include "ia64_table.h"
#undef _S
} };
static const struct transtab ia64_syscalltab[] = {
#define _S(n, s) { n, offsetof(union ia64_syscalltab_msgstr_t,  \
                               MSGSTRFIELD(__LINE__)) },
#include "ia64_table.h"
#undef _S
};
#define AUDIT_IA64_SYSCALL_NAMES (sizeof(ia64_syscalltab)/sizeof(ia64_syscalltab[0]))

static const union alpha_syscalltab_msgstr_t {
    struct {
#define _S(n, s) char MSGSTRFIELD(__LINE__)[sizeof (s)];
#include "alpha_table.h"
#undef _S
    };
    char str[0];
} alpha_syscalltab_msgstr = { {
#define _S(n, s) s,
#include "alpha_table.h"
#undef _S
} };
static const struct transtab alpha_syscalltab[] = {
#define _S(n, s) { n, offsetof(union alpha_syscalltab_msgstr_t,  \
                               MSGSTRFIELD(__LINE__)) },
#include "alpha_table.h"
#undef _S
};
#define AUDIT_ALPHA_SYSCALL_NAMES (sizeof(alpha_syscalltab)/sizeof(alpha_syscalltab[0]))


static const union fieldtab_msgstr_t {
    struct {
#define _S(n, s) char MSGSTRFIELD(__LINE__)[sizeof (s)];
#include "fieldtab.h"
#undef _S
    };
    char str[0];
} fieldtab_msgstr = { {
#define _S(n, s) s,
#include "fieldtab.h"
#undef _S
} };
static const struct transtab fieldtab[] = {
#define _S(n, s) { n, offsetof(union fieldtab_msgstr_t,  \
                               MSGSTRFIELD(__LINE__)) },
#include "fieldtab.h"
#undef _S
};
#define AUDIT_FIELD_NAMES (sizeof(fieldtab)/sizeof(fieldtab[0]))

static const union flagtab_msgstr_t {
    struct {
#define _S(n, s) char MSGSTRFIELD(__LINE__)[sizeof (s)];
#include "flagtab.h"
#undef _S
    };
    char str[0];
} flagtab_msgstr = { {
#define _S(n, s) s,
#include "flagtab.h"
#undef _S
} };
static const struct transtab flagtab[] = {
#define _S(n, s) { n, offsetof(union flagtab_msgstr_t,  \
                               MSGSTRFIELD(__LINE__)) },
#include "flagtab.h"
#undef _S
};
#define AUDIT_FLAG_NAMES (sizeof(flagtab)/sizeof(flagtab[0]))

static const union actiontab_msgstr_t {
    struct {
#define _S(n, s) char MSGSTRFIELD(__LINE__)[sizeof (s)];
#include "actiontab.h"
#undef _S
    };
    char str[0];
} actiontab_msgstr = { {
#define _S(n, s) s,
#include "actiontab.h"
#undef _S
} };
static const struct transtab actiontab[] = {
#define _S(n, s) { n, offsetof(union actiontab_msgstr_t,  \
                               MSGSTRFIELD(__LINE__)) },
#include "actiontab.h"
#undef _S
};
#define AUDIT_ACTION_NAMES (sizeof(actiontab)/sizeof(actiontab[0]))

static const union msg_typetab_msgstr_t {
    struct {
#define _S(n, s) char MSGSTRFIELD(__LINE__)[sizeof (s)];
#include "msg_typetab.h"
#undef _S
    };
    char str[0];
} msg_typetab_msgstr = { {
#define _S(n, s) s,
#include "msg_typetab.h"
#undef _S
} };
static const struct transtab msg_typetab[] = {
#define _S(n, s) { n, offsetof(union msg_typetab_msgstr_t,  \
                               MSGSTRFIELD(__LINE__)) },
#include "msg_typetab.h"
#undef _S
};
#define AUDIT_MSG_TYPE_NAMES (sizeof(msg_typetab)/sizeof(msg_typetab[0]))

static const union machinetab_msgstr_t {
    struct {
#define _S(n, s) char MSGSTRFIELD(__LINE__)[sizeof (s)];
#include "machinetab.h"
#undef _S
    };
    char str[0];
} machinetab_msgstr = { {
#define _S(n, s) s,
#include "machinetab.h"
#undef _S
} };
static const struct transtab machinetab[] = {
#define _S(n, s) { n, offsetof(union machinetab_msgstr_t,  \
                               MSGSTRFIELD(__LINE__)) },
#include "machinetab.h"
#undef _S
};
#define AUDIT_MACHINE_NAMES (sizeof(machinetab)/sizeof(machinetab[0]))

static const struct int_transtab elftab[] = {
    { MACH_X86,     AUDIT_ARCH_I386   },
    { MACH_86_64,   AUDIT_ARCH_X86_64 },
    { MACH_IA64,    AUDIT_ARCH_IA64   },
    { MACH_PPC64,   AUDIT_ARCH_PPC64  },
    { MACH_PPC,     AUDIT_ARCH_PPC    },
    { MACH_S390X,   AUDIT_ARCH_S390X  },
    { MACH_S390,    AUDIT_ARCH_S390   },
    { MACH_ALPHA,   AUDIT_ARCH_ALPHA  }
};
#define AUDIT_ELF_NAMES (sizeof(elftab)/sizeof(elftab[0]))

static const union optab_msgstr_t {
    struct {
#define _S(n, s) char MSGSTRFIELD(__LINE__)[sizeof (s)];
#include "optab.h"
#undef _S
    };
    char str[0];
} optab_msgstr = { {
#define _S(n, s) s,
#include "optab.h"
#undef _S
} };
static const struct transtab optab[] = {
#define _S(n, s) { n, offsetof(union optab_msgstr_t,  \
                               MSGSTRFIELD(__LINE__)) },
#include "optab.h"
#undef _S
};
#define AUDIT_NUM_OPERATORS (sizeof(optab)/sizeof(optab[0]))

static int audit_lookup_name(const struct transtab *table, const char *tabstr,
                             size_t length, const char *name)
{
	size_t i;
    
	for (i = 0; i < length; i++)
		if (!strcasecmp(tabstr + table[i].offset, name))
			return table[i].value;
	return -1;
}

static const char *audit_lookup_number(const struct transtab *table,
                                       const char *tabstr, size_t length,
                                       int number)
{
	size_t i;
    
	for (i = 0; i < length; i++)
		if (table[i].value == number)
			return tabstr + table[i].offset;
	return NULL;
}

int audit_name_to_field(const char *field)
{
	return audit_lookup_name(fieldtab, fieldtab_msgstr.str,
                                 AUDIT_FIELD_NAMES, field);
}

const char *audit_field_to_name(int field)
{
	return audit_lookup_number(fieldtab, fieldtab_msgstr.str,
                                   AUDIT_FIELD_NAMES, field);
}

int audit_name_to_syscall(const char *sc, int machine)
{
	switch (machine)
	{
		case MACH_X86:
    			return audit_lookup_name(i386_syscalltab, 
					i386_syscalltab_msgstr.str,
					AUDIT_I386_SYSCALL_NAMES, sc);
		case MACH_86_64:
    			return audit_lookup_name(x86_64_syscalltab, 
					x86_64_syscalltab_msgstr.str,
					AUDIT_X86_64_SYSCALL_NAMES, sc);
		case MACH_IA64:
    			return audit_lookup_name(ia64_syscalltab, 
					ia64_syscalltab_msgstr.str,
					AUDIT_IA64_SYSCALL_NAMES, sc);
		case MACH_PPC64:
		case MACH_PPC:
    			return audit_lookup_name(ppc_syscalltab, 
					ppc_syscalltab_msgstr.str,
					AUDIT_PPC_SYSCALL_NAMES, sc);
		case MACH_S390X:
    			return audit_lookup_name(s390x_syscalltab, 
					s390x_syscalltab_msgstr.str,
					AUDIT_S390X_SYSCALL_NAMES, sc);
		case MACH_S390:
    			return audit_lookup_name(s390_syscalltab, 
					s390_syscalltab_msgstr.str,
					AUDIT_S390_SYSCALL_NAMES, sc);
	        case MACH_ALPHA:
	                return audit_lookup_name(alpha_syscalltab,
					alpha_syscalltab_msgstr.str,
					AUDIT_ALPHA_SYSCALL_NAMES, sc);
	}
	return -1;
}

const char *audit_syscall_to_name(int sc, int machine)
{
	switch (machine)
	{
		case MACH_X86:
    			return audit_lookup_number(i386_syscalltab, 
					i386_syscalltab_msgstr.str,
					AUDIT_I386_SYSCALL_NAMES, sc);
		case MACH_86_64:
    			return audit_lookup_number(x86_64_syscalltab, 
					x86_64_syscalltab_msgstr.str,
					AUDIT_X86_64_SYSCALL_NAMES, sc);
		case MACH_IA64:
    			return audit_lookup_number(ia64_syscalltab, 
					ia64_syscalltab_msgstr.str,
					AUDIT_IA64_SYSCALL_NAMES, sc);
		case MACH_PPC64:
		case MACH_PPC:
    			return audit_lookup_number(ppc_syscalltab, 
					ppc_syscalltab_msgstr.str,
					AUDIT_PPC_SYSCALL_NAMES, sc);
		case MACH_S390X:
    			return audit_lookup_number(s390x_syscalltab,
					s390x_syscalltab_msgstr.str, 
					AUDIT_S390X_SYSCALL_NAMES, sc);
		case MACH_S390:
    			return audit_lookup_number(s390_syscalltab, 
					s390_syscalltab_msgstr.str,
					AUDIT_S390_SYSCALL_NAMES, sc);
	        case MACH_ALPHA:
	                return audit_lookup_number(alpha_syscalltab,
					alpha_syscalltab_msgstr.str,
					AUDIT_ALPHA_SYSCALL_NAMES, sc);
	}
	return NULL;
}

int audit_name_to_flag(const char *flag)
{
	return audit_lookup_name(flagtab, flagtab_msgstr.str,
				 AUDIT_FLAG_NAMES, flag);
}

const char *audit_flag_to_name(int flag)
{
	return audit_lookup_number(flagtab, flagtab_msgstr.str,
				   AUDIT_FLAG_NAMES, flag); 
}

int audit_name_to_action(const char *action)
{
	return audit_lookup_name(actiontab, actiontab_msgstr.str,
				 AUDIT_ACTION_NAMES, action);
}

const char *audit_action_to_name(int action)
{
	return audit_lookup_number(actiontab, actiontab_msgstr.str,
				   AUDIT_ACTION_NAMES, action);
}

// On the critical path for ausearch parser
int audit_name_to_msg_type(const char *msg_type)
{
	int rc = audit_lookup_name(msg_typetab, msg_typetab_msgstr.str,
				 AUDIT_MSG_TYPE_NAMES, msg_type);
	if (rc >= 0)
		return rc;

	/* Take a stab at converting */
	if (strncmp(msg_type, "UNKNOWN[", 8) == 0) {
		int len;
		char buf[8];
		const char *end = strchr(msg_type + 8, ']');
		if (end == NULL)
			return -1;

		len = end - (msg_type + 8);
		if (len > 7)
			len = 7;
		memset(buf, 0, sizeof(buf));
		strncpy(buf, msg_type + 8, len);

		return strtol(buf, NULL, 10);
	}
	return rc;
}

const char *audit_msg_type_to_name(int msg_type)
{
	return audit_lookup_number(msg_typetab, msg_typetab_msgstr.str,
				   AUDIT_MSG_TYPE_NAMES, msg_type);
}

int audit_name_to_machine(const char *machine)
{
	return audit_lookup_name(machinetab, machinetab_msgstr.str,
				 AUDIT_MACHINE_NAMES, machine);
}

const char *audit_machine_to_name(int machine)
{
	return audit_lookup_number(machinetab, machinetab_msgstr.str,
				   AUDIT_MACHINE_NAMES, machine);
}

unsigned int audit_machine_to_elf(int machine)
{
	unsigned int i;
    
	for (i = 0; i < AUDIT_ELF_NAMES; i++)
		if (elftab[i].key == machine) 
			return elftab[i].lvalue;
	return 0;
}

int audit_elf_to_machine(unsigned int elf)
{
	unsigned int i;
    
	for (i = 0; i < AUDIT_ELF_NAMES; i++) 
		if (elftab[i].lvalue == elf) return elftab[i].key;
	return -1;
}

const char *audit_operator_to_symbol(int op)
{
	/* Convert legacy ops */
	if (op == 0)
		op = AUDIT_EQUAL;
	else if (op & AUDIT_NEGATE)
		op = AUDIT_NOT_EQUAL;
	return audit_lookup_number(optab, optab_msgstr.str,
				   AUDIT_NUM_OPERATORS, op);
}

