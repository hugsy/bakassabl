PROGNAME                =       \"bakassabl\"
AUTHOR                  =       \"hugsy\"
LICENSE                 =       \"GPLv2\"
VERSION_MAJOR           =       0
VERSION_MINOR           =       1
VERSION_REL             =       git
VERSION                 =       \"$(VERSION_MAJOR).$(VERSION_MINOR)-$(VERSION_REL)\"
ARCH                    =       $(shell uname)

CC                      =       cc
BIN                     =       bakassabl
DEFINES                 =       -DPROGNAME=$(PROGNAME) -DVERSION=$(VERSION) -DAUTHOR=$(AUTHOR) -DLICENSE=$(LICENSE)
CHARDEN                 =       -fstack-protector-all -fPIE -fPIC
LHARDEN                 =       -Wl,-z,relro -pie
LDFLAGS                 =       -lseccomp $(LHARDEN)
SRC                     =       $(wildcard *.c)
OBJECTS                 =       $(patsubst %.c, %.o, $(SRC))
INC                     =       -I/usr/include
CFLAGS                  =       -Werror $(DEFINES) $(INC) $(CHARDEN) -O3
LIB                     =       -L/lib


.PHONY : all install uninstall clean purge test

.c.o :
	@echo "[+] CC $< -> $@"
	@$(CC) $(CFLAGS) -c -o $@ $<

all :  gen-header $(BIN)

gen-header:
	@bash gen_bakassabl.h.sh > bakassabl.h

$(BIN): $(OBJECTS)
	@echo "[+] LINK with $(LDFLAGS)"
	@$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(LIB) $(LDFLAGS)

clean:
	@echo "[+] RM objects"
	@rm -fr $(OBJECTS) *core* *~ *.swp

purge: clean
	@echo "[+] RM $(BIN)"
	@rm -fr $(BIN)

install: $(BIN)
	install -s -m 755 -o root -g root -- ./$(BIN) /usr/local/bin/

uninstall: clean
	rm -fr /usr/local/bin/$(BIN)

test: clean all
	./$(BIN) --verbose --paranoid  -- /bin/ping -c 10 localhost
	./$(BIN) --verbose --allow-all --deny connect -- /usr/bin/ncat -v4 localhost 22
	./$(BIN) --verbose --allow-all --deny connect -- /bin/cat /etc/passwd
