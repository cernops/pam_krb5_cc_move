CC=gcc
CFLAGS="-fPIC -fno-stack-protector"
INSTALLDIR=/usr/lib64/security
MANDIR=/usr/share/man

all: pam_krb5_cc_move.so

src/pam_krb5_cc_move.o: src/pam_krb5_cc_move.c
	gcc $(EXTRA_CFLAGS) -fPIC -fno-stack-protector -c src/pam_krb5_cc_move.c -o src/pam_krb5_cc_move.o

pam_krb5_cc_move.so: src/pam_krb5_cc_move.o
	gcc $(EXTRA_CFLAGS) -shared -o pam_krb5_cc_move.so src/pam_krb5_cc_move.o -lpam -lkrb5

install: all
	install -d $(DESTDIR)$(MANDIR)/man8
	install -p -m 0644 man/pam_krb5_cc_move.8 $(DESTDIR)$(MANDIR)/man8/pam_krb5_cc_move.8
	install -d $(DESTDIR)$(MANDIR)/$(INSTALLDIR)
	install -p -m 0755 pam_krb5_cc_move.so $(DESTDIR)/$(INSTALLDIR)/pam_krb5_cc_move.so 

clean:
	rm -rf build/ $(TARFILE) src/*.o *.so

