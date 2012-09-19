CFLAGS=-g -W -Wall -Wundef -I..

LIBS=-lauparse -laudit

all: auparse_test
auparse_test: auparse_test.c
	gcc $(CFLAGS) auparse_test.c -o auparse_test -static -L../.libs/ -L../../lib/.libs $(LIBS)

check: auparse_test ../.libs/libauparse.a
	./auparse_test 
clean:
	rm -f auparse_test *.o *.txt
