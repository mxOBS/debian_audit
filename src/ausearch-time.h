/* ausearch-time.h - header file for ausearch-time.c
 * Copyright 2006 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *     Steve Grubb <sgrubb@redhat.com>
 */

#ifndef AUSEARCH_TIME_HEADERS
#define AUSEARCH_TIME_HEADERS

#include <time.h>

enum {  T_NOW, T_RECENT, T_TODAY, T_YESTERDAY, T_THIS_WEEK, T_THIS_MONTH,
	T_THIS_YEAR };

extern time_t start_time, end_time;

int lookup_time(const char *name);
void clear_tm(struct tm *t);
void set_tm_now(struct tm *d);
void set_tm_recent(struct tm *d);
void set_tm_today(struct tm *d);
void set_tm_yesterday(struct tm *d);
void set_tm_this_week(struct tm *d);
void set_tm_this_month(struct tm *d);
void set_tm_this_year(struct tm *d);
void add_tm(struct tm *d, struct tm *t);
void replace_time(struct tm *t1, struct tm *t2);
void replace_date(struct tm *t1, struct tm *t2);
void set_time(struct tm *t, int num, const char *t1, const char *t2);
int ausearch_time_start(const char *da, const char *ti);
int ausearch_time_end(const char *da, const char *ti);

#endif

