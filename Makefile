PROGNAME=s91187
SSLDIR=/usr
SSLLIBFLAGS=-lcrypto
SSLFLAGS=-L $(SSLDIR) -isystem $(SSLDIR)/include

s91187:
	cc -g -Wall $(SSLFLAGS) $(PROGNAME).c $(SSLLIBFLAGS) -o $(PROGNAME)

macos:
	cc -g -Wall $(SSLFLAGS) $(PROGNAME).c $(SSLLIBFLAGS) -o $(PROGNAME)
	install_name_tool -change /usr/local/lib/libcrypto.3.dylib $(SSLDIR)/libcrypto.3.dylib $(PROGNAME)

run:
	@LD_LIBRARY_PATH=$(SSLDIR) ./$(PROGNAME)
