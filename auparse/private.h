/* private.h -- 
 * Copyright 2007 Red Hat Inc., Durham, North Carolina.
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
#ifndef _PRIVATE_H_
#define _PRIVATE_H_

#ifdef __cplusplus
extern "C" {
#endif

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

/* Internal syslog messaging */
#define audit_msg auparse_msg
#define set_aumessage_mode set_aup_message_mode
void auparse_msg(int priority, const char *fmt, ...)
#ifdef __GNUC__
        __attribute__ ((format (printf, 2, 3)));
#else
        ;
#endif

hidden_proto(audit_msg)

#ifdef __cplusplus
}
#endif

#endif

