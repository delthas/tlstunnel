.POSIX:
.SUFFIXES:

GO = go
RM = rm
SCDOC = scdoc
GOFLAGS =
PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/share/man

all: tlstunnel tlstunnel.1

tlstunnel:
	$(GO) build $(GOFLAGS) ./cmd/tlstunnel
tlstunnel.1: tlstunnel.1.scd
	$(SCDOC) <tlstunnel.1.scd >tlstunnel.1

clean:
	$(RM) -rf tlstunnel doc/tlstunnel.1
install: all
	mkdir -p $(DESTDIR)$(BINDIR)
	mkdir -p $(DESTDIR)$(MANDIR)/man1
	cp -f tlstunnel $(DESTDIR)$(BINDIR)
	cp -f tlstunnel.1 $(DESTDIR)$(MANDIR)/man1
