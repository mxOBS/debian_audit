#!/usr/bin/env python


buf = ["type=LOGIN msg=audit(1143146623.787:142): login pid=2027 uid=0 old auid=4294967295 new auid=48\ntype=SYSCALL msg=audit(1143146623.875:143): arch=c000003e syscall=188 success=yes exit=0 a0=7fffffa9a9f0 a1=3958d11333 a2=5131f0 a3=20 items=1 pid=2027 auid=48 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=tty3 comm=\"login\" exe=\"/bin/login\" subj=system_u:system_r:local_login_t:s0-s0:c0.c255",
"type=USER_LOGIN msg=audit(1143146623.879:146): user pid=2027 uid=0 auid=48 msg=\'uid=48: exe=\"/bin/login\" (hostname=?, addr=?, terminal=tty3 res=success)\'",
]
files = ["test.log", "test2.log"]

import os
import sys
import time
load_path = 'build/lib.linux-i686-2.4'
if False:
    sys.path.insert(0, load_path)

import auparse

def walk_test(au):
    event_cnt = 1

    au.reset()
    while True:
        if not au.first_record():
            print "Error getting first record"
            sys.exit(1)

        print "event: %d" % event_cnt
        print "records:%d" % au.get_num_records()

        while True:
            print "fields:%d" % au.get_num_fields()
            print "type=%d" % au.get_type(),
            event = au.get_timestamp()
            if event is None:
                print "Error getting timestamp - aborting"
                sys.exit(1)

            print "event time: %d.%d:%d" % (event.sec, event.milli, event.serial)
            au.first_field()
            while True:
                print "%s=%s (%s)" % (au.get_field_name(), au.get_field_str(), au.interpret_field())
                if not au.next_field(): break
            print
            if not au.next_record(): break
        event_cnt += 1
        if not au.parse_next_event(): break


def light_test(au):
    while True:
        if not au.first_record():
            print "Error getting first record"
            sys.exit(1)

        print "records:%d" % au.get_num_records()

        while True:
            print "fields:%d" % au.get_num_fields()
            print "type=%d" % au.get_type(),
            event = au.get_timestamp()
            if event is None:
                print "Error getting timestamp - aborting"
                sys.exit(1)

            print "event time: %d.%d:%d" % (event.sec, event.milli, event.serial)
            print
            if not au.next_record(): break
        if not au.parse_next_event(): break

def simple_search(au, source, where):

    if source == auparse.AUSOURCE_FILE:
        au = auparse.AuParser(auparse.AUSOURCE_FILE, "./test.log");
        val = "4294967295"
    else:
        au = auparse.AuParser(auparse.AUSOURCE_BUFFER_ARRAY, buf)
        val = "48"

    au.search_add_item("auid", "=", val, auparse.AUSEARCH_RULE_CLEAR)
    au.search_set_stop(where)
    if not au.search_next_event():
        print "Error searching for auid"
    else:
        print "Found %s = %s" % (au.get_field_name(), au.get_field_str())

def compound_search(au, how):
    au = auparse.AuParser(auparse.AUSOURCE_FILE, "./test.log");
    if how == auparse.AUSEARCH_RULE_AND:
        au.search_add_item("uid", "=", "0", auparse.AUSEARCH_RULE_CLEAR)
        au.search_add_item("pid", "=", "13015", how)
        au.search_add_item("type", "=", "USER_START", how)
    else:
        au.search_add_item("auid", "=", "42", auparse.AUSEARCH_RULE_CLEAR)
        # should stop on this one
        au.search_add_item("auid", "=", "0", how)
        au.search_add_item("auid", "=", "500", how)

    au.search_set_stop(auparse.AUSEARCH_STOP_FIELD)
    if not au.search_next_event():
        print "Error searching for auid"
    else:
        print "Found %s = %s" % (au.get_field_name(), au.get_field_str())



au = auparse.AuParser(auparse.AUSOURCE_BUFFER_ARRAY, buf)

print "Starting Test 1, iterate..."
while au.parse_next_event():
    if au.find_field("auid"):
        print "%s=%s" % (au.get_field_name(), au.get_field_str())
        print "interp auid=%s" % (au.interpret_field())
    else:
        print "Error iterating to auid"
print "Test 1 Done\n"

# Reset, now lets go to beginning and walk the list manually */
print "Starting Test 2, walk events, records, and fields..."
walk_test(au)
print "Test 2 Done\n"

# Reset, now lets go to beginning and walk the list manually */
print "Starting Test 3, walk events, records of 1 buffer..."
au = auparse.AuParser(auparse.AUSOURCE_BUFFER, buf[1])
light_test(au);
print "Test 3 Done\n"

print "Starting Test 4, walk events, records of 1 file..."
au = auparse.AuParser(auparse.AUSOURCE_FILE, "./test.log");
walk_test(au); 
print "Test 4 Done\n"

print "Starting Test 5, walk events, records of 2 files..."
au = auparse.AuParser(auparse.AUSOURCE_FILE_ARRAY, files);
walk_test(au); 
print "Test 5 Done\n"

print "Starting Test 6, search..."
au = auparse.AuParser(auparse.AUSOURCE_BUFFER_ARRAY, buf)
au.search_add_item("auid", "=", "500", auparse.AUSEARCH_RULE_CLEAR)
au.search_set_stop(auparse.AUSEARCH_STOP_EVENT)
if au.search_next_event():
    print "Error search found something it shouldn't have"
else:
    print "auid = 500 not found...which is correct"
au.search_clear()
au = auparse.AuParser(auparse.AUSOURCE_BUFFER_ARRAY, buf)
#au.search_add_item("auid", "exists", None, auparse.AUSEARCH_RULE_CLEAR)
au.search_add_item("auid", "exists", "", auparse.AUSEARCH_RULE_CLEAR)
au.search_set_stop(auparse.AUSEARCH_STOP_EVENT)
if not au.search_next_event():
    print "Error searching for existence of auid"
print "auid exists...which is correct"
print "Testing BUFFER_ARRAY, stop on field"
simple_search(au, auparse.AUSOURCE_BUFFER_ARRAY, auparse.AUSEARCH_STOP_FIELD)
print "Testing BUFFER_ARRAY, stop on record"
simple_search(au, auparse.AUSOURCE_BUFFER_ARRAY, auparse.AUSEARCH_STOP_RECORD)
print "Testing BUFFER_ARRAY, stop on event"
simple_search(au, auparse.AUSOURCE_BUFFER_ARRAY, auparse.AUSEARCH_STOP_EVENT)
print "Testing test.log, stop on field"
simple_search(au, auparse.AUSOURCE_FILE, auparse.AUSEARCH_STOP_FIELD)
print "Testing test.log, stop on record"
simple_search(au, auparse.AUSOURCE_FILE, auparse.AUSEARCH_STOP_RECORD)
print "Testing test.log, stop on event"
simple_search(au, auparse.AUSOURCE_FILE, auparse.AUSEARCH_STOP_EVENT)
print "Test 6 Done\n"

print "Starting Test 7, compound search..."
au = auparse.AuParser(auparse.AUSOURCE_BUFFER_ARRAY, buf)
compound_search(au, auparse.AUSEARCH_RULE_AND)
compound_search(au, auparse.AUSEARCH_RULE_OR)
print "Test 7 Done\n"

if (os.getuid() != 0):
    print "Finished non-admin tests"
    sys.exit(0)

print "Starting Test 8, walk events, records of logs..."
au = auparse.AuParser(auparse.AUSOURCE_LOGS)
light_test(au)
print "Test 8 Done\n"
sys.exit(0)

