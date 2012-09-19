# Makefile.am -- 
# Copyright 2006-07 Red Hat Inc., Durham, North Carolina.
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

#SUBDIRS = test
CONFIG_CLEAN_FILES = Makefile.in *.loT *.rej *.orig
AM_CFLAGS = -fPIC -DPIC -D_GNU_SOURCE
INCLUDES = -I. -I.. -I../src -I../lib
LIBS =
lib_LTLIBRARIES = libauparse.la
include_HEADERS = auparse.h auparse-defs.h
libauparse_la_SOURCES = rlist.c nvpair.c interpret.c nvlist.c ellist.c \
	auparse.c auditd-config.c message.c \
	captab.h famtab.h flagtab.h ipctab.h socktab.h typetab.h \
	open-flagtab.h clone-flagtab.h fcntl-cmdtab.h 
libauparse_la_LIBADD =
libauparse_la_DEPENDENCIES = $(libauparse_la_SOURCES) ../config.h
libauparse_la_LDFLAGS = -Wl,-z,relro

message.c:
	cp ${top_srcdir}/lib/message.c .

