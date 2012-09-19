#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <locale.h>
#include <errno.h>
#include <auparse.h>


static const char *buf[] = {
		"type=LOGIN msg=audit(1143146623.787:142): login pid=2027 uid=0 old auid=4294967295 new auid=48\ntype=SYSCALL msg=audit(1143146623.875:143): arch=c000003e syscall=188 success=yes exit=0 a0=7fffffa9a9f0 a1=3958d11333 a2=5131f0 a3=20 items=1 pid=2027 auid=48 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=tty3 comm=\"login\" exe=\"/bin/login\" subj=system_u:system_r:local_login_t:s0-s0:c0.c255",

"type=USER_LOGIN msg=audit(1143146623.879:146): user pid=2027 uid=0 auid=48 msg=\'uid=48: exe=\"/bin/login\" (hostname=?, addr=?, terminal=tty3 res=success)\'",

		NULL
};


static void walk_test(auparse_state_t *au)
{
	int event_cnt = 1;

	auparse_reset(au);
	do {
		if (auparse_first_record(au) <= 0) {
			printf("Error getting first record (%s)\n",
						strerror(errno));
			exit(1);
		}
		printf("event: %d\n", event_cnt);
		printf("records:%d\n", auparse_get_num_records(au));
		do {
			printf("fields:%d\n", auparse_get_num_fields(au));
			printf("type=%d ", auparse_get_type(au));
			const au_event_t *e = auparse_get_timestamp(au);
			if (e == NULL) {
				printf("Error getting timestamp - aborting\n");
				exit(1);
			}
			printf("event time: %u.%u:%lu\n", (unsigned)e->sec,
						 e->milli, e->serial);
			auparse_first_field(au);
			do {
				printf("%s=%s (%s)\n",
						auparse_get_field_name(au),
						auparse_get_field_str(au),
						auparse_interpret_field(au));
			} while (auparse_next_field(au) > 0);
			printf("\n");

		} while(auparse_next_record(au) > 0);
		event_cnt++;
	} while (auparse_next_event(au) > 0);
}

void light_test(auparse_state_t *au)
{
	do {
		if (auparse_first_record(au) <= 0) {
			puts("Error getting first record");
			exit(1);
		}
		printf("records:%d\n", auparse_get_num_records(au));
		do {
			printf("fields:%d\n", auparse_get_num_fields(au));
			printf("type=%d ", auparse_get_type(au));
			const au_event_t *e = auparse_get_timestamp(au);
			if (e == NULL) {
				printf("Error getting timestamp - aborting\n");
				exit(1);
			}
			printf("event time: %u.%u:%lu\n", (unsigned)e->sec,
						 e->milli, e->serial);
			printf("\n");

		} while(auparse_next_record(au) > 0);

	} while (auparse_next_event(au) > 0);
}

void simple_search(auparse_state_t *au, ausource_t source, austop_t where)
{
	const char *val;

	ausearch_clear(au);
	auparse_reset(au);
	if (source == AUSOURCE_FILE) {
		au = auparse_init(AUSOURCE_FILE, "./test.log");
		val = "4294967295";
	} else {
		au = auparse_init(AUSOURCE_BUFFER_ARRAY, buf);
		val = "48";
	}
	if (au == NULL) {
		printf("auparse_init error - %s\n", strerror(errno));
		exit(1);
	}
	if (ausearch_add_item(au, "auid", "=", val, AUSEARCH_RULE_CLEAR)){
		printf("ausearch_add_item error - %s\n", strerror(errno));
		exit(1);
	}
	if (ausearch_set_stop(au, where)){
		printf("ausearch_set_stop error - %s\n", strerror(errno));
		exit(1);
	}
	if (ausearch_next_event(au) <= 0)
		printf("Error searching for auid - %s\n", strerror(errno));
	else
		printf("Found %s = %s\n", auparse_get_field_name(au),
					auparse_get_field_str(au));
}

void compound_search(auparse_state_t *au, ausearch_rule_t how)
{
	ausearch_clear(au);
	auparse_reset(au);
	au = auparse_init(AUSOURCE_FILE, "./test.log");
	if (au == NULL) {
		printf("auparse_init error - %s\n", strerror(errno));
		exit(1);
	}
	if (how == AUSEARCH_RULE_AND) {
		if (ausearch_add_item(au, "uid", "=", "0",
							 AUSEARCH_RULE_CLEAR)){
			printf("ausearch_add_item 1 error - %s\n",
						strerror(errno));
			exit(1);
		}
		if (ausearch_add_item(au, "pid", "=", "13015", how)){
			printf("ausearch_add_item 2 error - %s\n",
						strerror(errno));
			exit(1);
		}
		if (ausearch_add_item(au, "type", "=", "USER_START", how)){
			printf("ausearch_add_item 3 error - %s\n",
						strerror(errno));
			exit(1);
		}
	} else {
		if (ausearch_add_item(au, "auid", "=", "42",
							 AUSEARCH_RULE_CLEAR)){
			printf("ausearch_add_item 4 error - %s\n",
						strerror(errno));
			exit(1);
		}
		// should stop on this one
		if (ausearch_add_item(au, "auid", "=", "0", how)){
			printf("ausearch_add_item 5 error - %s\n",
						strerror(errno));
			exit(1);
		}
		if (ausearch_add_item(au, "auid", "=", "500", how)){
			printf("ausearch_add_item 6 error - %s\n",
						strerror(errno));
			exit(1);
		}
	}
	if (ausearch_set_stop(au, AUSEARCH_STOP_FIELD)){
		printf("ausearch_set_stop error - %s\n", strerror(errno));
		exit(1);
	}
	if (ausearch_next_event(au) <= 0)
		printf("Error searching for auid - %s\n", strerror(errno));
	else
		printf("Found %s = %s\n", auparse_get_field_name(au),
					auparse_get_field_str(au));
}

int main(void)
{
	//char *files[4] = { "test.log", "test2.log", "test3.log", NULL };
	char *files[3] = { "test.log", "test2.log", NULL };
	setlocale (LC_ALL, "");

	auparse_state_t *au = auparse_init(AUSOURCE_BUFFER_ARRAY, buf);
	if (au == NULL) {
		printf("Error - %s\n", strerror(errno));
		return 1;
	}

	printf("Starting Test 1, iterate...\n");
	while (auparse_next_event(au) > 0) {
		if (auparse_find_field(au, "auid")) {
			printf("%s=%s\n", auparse_get_field_name(au),
					  auparse_get_field_str(au));
			printf("interp auid=%s\n", auparse_interpret_field(au));
		} else 
			printf("Error iterating to auid\n");
	}
	printf("Test 1 Done\n\n");

	/* Reset, now lets go to beginning and walk the list manually */
	printf("Starting Test 2, walk events, records, and fields...\n");
	auparse_reset(au);
	walk_test(au);
	printf("Test 2 Done\n\n");

	/* Reset, now lets go to beginning and walk the list manually */
	printf("Starting Test 3, walk events, records of 1 buffer...\n");
	auparse_destroy(au);
	au = auparse_init(AUSOURCE_BUFFER, buf[1]);
	if (au == NULL) {
		printf("Error - %s\n", strerror(errno));
		return 1;
	}
	light_test(au);
	printf("Test 3 Done\n\n");

	printf("Starting Test 4, walk events, records of 1 file...\n");
	auparse_destroy(au);
	au = auparse_init(AUSOURCE_FILE, "./test.log");
	if (au == NULL) {
		printf("Error - %s\n", strerror(errno));
		return 1;
	}
	walk_test(au); 
	printf("Test 4 Done\n\n");

	printf("Starting Test 5, walk events, records of 2 files...\n");
	auparse_destroy(au);
	au = auparse_init(AUSOURCE_FILE_ARRAY, files);
	if (au == NULL) {
		printf("Error - %s\n", strerror(errno));
		return 1;
	}
	walk_test(au); 
	printf("Test 5 Done\n\n");

	printf("Starting Test 6, search...\n");
	auparse_destroy(au);
	au = auparse_init(AUSOURCE_BUFFER_ARRAY, buf);
	if (au == NULL) {
		printf("Error - %s\n", strerror(errno));
		return 1;
	}
	if (ausearch_add_item(au, "auid", "=", "500", AUSEARCH_RULE_CLEAR)){
		printf("Error - %s", strerror(errno));
		return 1;
	}
	if (ausearch_set_stop(au, AUSEARCH_STOP_EVENT)){
		printf("Error - %s", strerror(errno));
		exit(1);
	}
	if (ausearch_next_event(au) != 0) {
		printf("Error search found something it shouldn't have\n");
	}
	puts("auid = 500 not found...which is correct");
	ausearch_clear(au);
	auparse_destroy(au);
	au = auparse_init(AUSOURCE_BUFFER_ARRAY, buf);
	if (ausearch_add_item(au,"auid", "exists", NULL, AUSEARCH_RULE_CLEAR)){
		printf("Error - %s", strerror(errno));
		return 1;
	}
	if (ausearch_set_stop(au, AUSEARCH_STOP_EVENT)){
		printf("Error - %s", strerror(errno));
		exit(1);
	}
	if (ausearch_next_event(au) <= 0) {
		printf("Error searching for existence of auid\n");
	}
	puts("auid exists...which is correct");
	puts("Testing BUFFER_ARRAY, stop on field");
	simple_search(au, AUSOURCE_BUFFER_ARRAY, AUSEARCH_STOP_FIELD);
	puts("Testing BUFFER_ARRAY, stop on record");
	simple_search(au, AUSOURCE_BUFFER_ARRAY, AUSEARCH_STOP_RECORD);
	puts("Testing BUFFER_ARRAY, stop on event");
	simple_search(au, AUSOURCE_BUFFER_ARRAY, AUSEARCH_STOP_EVENT);
	puts("Testing test.log, stop on field");
	simple_search(au, AUSOURCE_FILE, AUSEARCH_STOP_FIELD);
	puts("Testing test.log, stop on record");
	simple_search(au, AUSOURCE_FILE, AUSEARCH_STOP_RECORD);
	puts("Testing test.log, stop on event");
	simple_search(au, AUSOURCE_FILE, AUSEARCH_STOP_EVENT);
	printf("Test 6 Done\n\n");
	
	printf("Starting Test 7, compound search...\n");
	auparse_destroy(au);
	au = auparse_init(AUSOURCE_BUFFER_ARRAY, buf);
	if (au == NULL) {
		printf("Error - %s\n", strerror(errno));
		return 1;
	}
	compound_search(au, AUSEARCH_RULE_AND);
	compound_search(au, AUSEARCH_RULE_OR);
	printf("Test 7 Done\n\n");


	if (getuid() != 0) {
		puts("Finished non-admin tests\n");
		return 0;
	}
	printf("Starting Test 8, walk events, records of logs...\n");
	auparse_destroy(au);
	au = auparse_init(AUSOURCE_LOGS, NULL);
	if (au == NULL) {
		printf("Error - %s\n", strerror(errno));
		return 1;
	}
	light_test(au);
	printf("Test 8 Done\n\n");

	auparse_destroy(au);
	return 0;
}

