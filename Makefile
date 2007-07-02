libnss_sqlite.so.2: groups.o passwd.o shadow.o utils.o
	gcc $(CFLAGS) -lsqlite3 -shared -o libnss_sqlite.so.2 -Wl,-soname,libnss_sqlite.so.2 groups.o passwd.o shadow.o utils.o

groups.o: groups.c nss-sqlite.h utils.h
	gcc $(CFLAGS) -c groups.c

passwd.o: passwd.c nss-sqlite.h utils.h
	gcc $(CFLAGS) -c passwd.c

shadow.o: shadow.c nss-sqlite.h utils.h
	gcc $(CFLAGS) -c shadow.c

utils.o: utils.c nss-sqlite.h utils.h
	gcc $(CFLAGS) -c utils.c 

clean:
	rm *.o libnss_sqlite.so.2

.PHONY: clean
