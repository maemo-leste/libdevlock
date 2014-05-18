PREFIX := /usr
LIBDIR := $(PREFIX)/lib
INCLUDEDIR := $(PREFIX)/include

install:
	install -d $(DESTDIR)$(LIBDIR)
	install -d $(DESTDIR)$(INCLUDEDIR)
	install libdevlock.h $(DESTDIR)$(INCLUDEDIR)
	ln -s libdevlock.so.1.0.9 $(DESTDIR)$(LIBDIR)/libdevlock.so
