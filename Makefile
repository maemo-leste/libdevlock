LIB_VERSION=0.9

BINDIR := /bin
PREFIX := /usr
LIBDIR := $(PREFIX)/lib
INCLUDEDIR := $(PREFIX)/include
PKGCONFIGDIR = $(LIBDIR)/pkgconfig
PACKAGES="gobject-2.0 glib-2.0 gconf-2.0 libcal"

INSTALL = install

INSTALL_INCLUDES = libdevlock.h
INSTALL_PKGCONFIG = libdevlock1.pc
INSTALL_LIBS = libdevlock.so.1.$(LIB_VERSION)
INSTALL_BINS = devlocktool


all: libdevlock.so.1.$(LIB_VERSION) devlocktool

libdevlock.so.1.0.9: libdevlock.c
	rm -f libdevlock.so.1
	$(CC) $(CFLAGS) $(LDFLAGS) -Wall -D_GNU_SOURCE -fPIC -shared $^ $(shell pkg-config --cflags --libs $(PACKAGES)) -lcrypt -Wl,-soname=libdevlock.so.1 -o $@
	ln -s libdevlock.so.1.$(LIB_VERSION) libdevlock.so.1

devlocktool: devlocktool.c
	$(CC) $(CFLAGS) $(LDFLAGS) -Wall -D_GNU_SOURCE -fPIC $^ $(shell pkg-config --cflags glib-2.0) -L./ -l:libdevlock.so.1 -o $@

test: test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -Wall -g -D_GNU_SOURCE -fPIC $^ $(shell pkg-config --cflags --libs $(PACKAGES)) -lcrypt -o $@

install:
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -d $(DESTDIR)$(LIBDIR)
	$(INSTALL) -d $(DESTDIR)$(INCLUDEDIR)
	$(INSTALL) -d $(DESTDIR)$(PKGCONFIGDIR)
	$(INSTALL) -m 4755 $(INSTALL_BINS) $(DESTDIR)$(BINDIR)
	$(INSTALL) $(INSTALL_INCLUDES) $(DESTDIR)$(INCLUDEDIR)
	$(INSTALL) $(INSTALL_LIBS) $(DESTDIR)$(LIBDIR)
	ln -s libdevlock.so.1.$(LIB_VERSION) $(DESTDIR)$(LIBDIR)/libdevlock.so.1
	$(INSTALL) $(INSTALL_PKGCONFIG) $(DESTDIR)$(PKGCONFIGDIR)

clean:
	$(RM) *.o *~ test devlocktool libdevlock.so.1 libdevlock.so.1.$(LIB_VERSION)
