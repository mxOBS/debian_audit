# Makefile.am -- 
# Copyright 2004-2006 Red Hat Inc., Durham, North Carolina.
# All Rights Reserved.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
# 
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
# 
# Authors:
#   Steve Grubb <sgrubb@redhat.com>
#

CONFIG_CLEAN_FILES = Makefile.in *.loT *.rej *.orig
AM_CFLAGS = -fPIC -DPIC -D_GNU_SOURCE
INCLUDES = -I. -I..
lib_LTLIBRARIES = libaudit.la
include_HEADERS = libaudit.h
libaudit_la_SOURCES = libaudit.c message.c netlink.c \
	lookup_table.c audit_logging.c deprecated.c \
	i386_table.h ia64_table.h ppc_table.h s390_table.h \
	s390x_table.h x86_64_table.h alpha_table.h \
	private.h actiontab.h fieldtab.h flagtab.h \
	machinetab.h msg_typetab.h optab.h
libaudit_la_LIBADD =
libaudit_la_DEPENDENCIES = $(libaudit_la_SOURCES) ../config.h
libaudit_la_LDFLAGS = -Wl,-z,relro
