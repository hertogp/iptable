# Makefile for iptable

# utilities
RM=/bin/rm
BUSTED=~/.luarocks/bin/busted
VGRIND=valgrind
VOPTS=--leak-check=full --show-leak-kinds=all
BOPTS=
MKDIR= mkdir
INSTALL= cp
IMAGINE=/home/pdh/dev/imagine/pandoc_imagine.py

# project directories
SRCDIR=src
TSTDIR=src/test
BLDDIR=build
DOCDIR=doc
BSDDIR=bsd


# Lua/luarocks directories
# - build dirs
# LUA_LIBDIR=
# LUA_BINDIR=
# LUA_INCDIR=
# LUALIB=
# LUA=
# - install dirs
INST_PREFIX=/usr/local
INST_BINDIR=$(INST_PREFIX)/bin
INST_LIBDIR=$(INST_PREFIX)/lib/lua/5.4
INST_LUADIR=$(INST_PREFIX)/share/lua/5.4
INST_CONFDIR=$(INST_PREFIX)/etc

# versioning
MAJOR=0
MINOR=0
PATCH=1
ROCKR=1
VERSION=$(MAJOR).$(MINOR).$(PATCH)

# library
LIB=iptable
SONAME=lib$(LIB).so.$(MAJOR)
TARGET=$(BLDDIR)/$(LIB).so
CTARGET=$(BLDDIR)/lib$(LIB).so

# C/LUA file collections
# note: lua_iptable.c must come last
FILES= radix.c iptable.c lua_iptable.c
DEPS=$(FILES:%.c=$(BLDDIR)/%.d)
SRCS=$(FILES:%.c=$(SRCDIR)/%.c)
OBJS=$(FILES:%.c=$(BLDDIR)/%.o)
COBJS=$(filter-out $(lastword $(OBJS)), $(OBJS))
DOCSRC=$(filter-out %radix.c, $(SRCS))
DOCS=$(DOCSRC:$(SRCDIR)/%.c=$(DOCDIR)/%.md)

# Flags
CFLAGS=  -std=gnu99
CFLAGS+= -O2 -g -fPIC
# CFLAGS+= -Wall -Wextra -Werror -pedantic
CFLAGS+= -Wall -Wextra -pedantic

# add more warnings
CFLAGS+= -Wno-unknown-warning-option -Wold-style-definition
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith
CFLAGS+= -Wmissing-declarations -Wredundant-decls -Wnested-externs
CFLAGS+= -Wshadow -Wcast-qual -Wcast-align -Wwrite-strings
CFLAGS+= -Wsuggest-attribute=noreturn -Wjump-misses-init -Wno-stringop-truncation

LIBFLAG= -shared
LFLAGS=  -fPIC
SOFLAG=  -Wl,-soname=$(SONAME)

# flag DEBUG=1
ifdef DEBUG
  CFLAGS+=-DDEBUG
  BOPTS=--defer-print
endif


# not real targets
.PHONY: clean DEBUG bsd

# dependency files are auto-generated and, normally, autodeleted
# unless defined as .SECONDARY's
.SECONDARY: $(DEPS)

# Lua library (default target)
$(TARGET): $(OBJS) $(DEPS)
	$(CC) $(LIBFLAG) $(LFLAGS) $(OBJS) -o $(TARGET)

lua_lib: $(TARGET)

c_lib: $(CTARGET)
# https://www.gnu.org/software/make/manual/html_node/Target_002dspecific.html
debug DEBUG: CFLAGS+=-DDEBUG
debug DEBUG: BOPTS=--defer-print
debug DEBUG: clean $(TARGET)

# C libary
$(CTARGET): $(COBJS)
	$(CC) $(LIBFLAG) $(LFLAGS) $(SOFLAG) $(COBJS) -o $(CTARGET).$(VERSION)
	ln -sf lib$(LIB).so.$(VERSION) $(BLDDIR)/lib$(LIB).so
	ln -sf lib$(LIB).so.$(VERSION) $(BLDDIR)/lib$(LIB).so.$(MAJOR)


$(BLDDIR):
	$(MKDIR) $(BLDDIR)

# object files
$(BLDDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -I$(SRCDIR) -c $< -o $@

# dependency files .d
# - built first before others, hence the only one made dependent on 
#   the existence of $BLDDIR
$(BLDDIR)/%.d: $(SRCDIR)/%.c | $(BLDDIR)
	$(CC) -I$(SRCDIR) -MM -MQ$(BLDDIR)/$*.o -MF $@ $<

# make install -or- luarocks install iptable
install: $(TARGET)
	$(INSTALL) $(TARGET) $(INST_LIBDIR)

local_install: $(TARGET)
	cp $(TARGET) ~/.luarocks/lib/lua/5.4/

uninstall: $(TARGET)
	$(RM) $(INST_LIBDIR)/$(TARGET)

clean:
	$(RM) $(BLDDIR)/*

# include the dependencies for the object files
-include $(DEPS)

# run all C- and LUA-unit tests
test: c_test lua_test

# run all Lua-unit tests
lua_test: $(TARGET)
	@echo "\n\n--- Lua unit tests ---\n"
	@$(BUSTED) $(BOPTS) .
	@echo "\n--- done ---\n\n"

# MINUT - C unit tests
MU_SOURCES=$(sort $(wildcard $(TSTDIR)/test_*.c))
MU_TARGETS=$(MU_SOURCES:$(TSTDIR)/%.c=%)
MU_HEADERS=$(MU_TARGETS:%=$(BLDDIR)/%.h)
MU_OBJECTS=$(MU_TARGETS:%=$(BLDDIR)/%.o)
MU_RUNNERS=$(MU_TARGETS:%=$(BLDDIR)/%.out)

# run all C-unit tests
c_test: $(CTARGET) $(MU_RUNNERS)
	@echo "\n\n--- C unit tests ---\n"
	#@$(foreach runner, $(MU_RUNNERS), valgrind --leak-check=yes ./$(runner);)
	@$(foreach runner, $(MU_RUNNERS), $(VGRIND) $(VOPTS) ./$(runner);)
	@echo "\n--- done ---\n\n"

# generate API documentation from code comments
POPTS=+lists_without_preceding_blankline

$(DOCS): $(DOCDIR)/%.md: $(SRCDIR)/%.c $(SRCDIR)/%.h
	grep -E "^(/\*| \*)" $(SRCDIR)/$*.h| cut --bytes=4- > $(DOCDIR)/$*.c.md
	grep -E "^(/\*| \*)" $(SRCDIR)/$*.c| cut --bytes=4- >> $(DOCDIR)/$*.c.md
	pandoc -f markdown$(POPTS) $(DOCDIR)/$*.c.md -o $(DOCDIR)/$*.c.pdf

readme:
	pandoc --filter $(IMAGINE) -f markdown -t gfm -o README.md _readme.md
	pandoc --filter $(IMAGINE) -f gfm README.md -o doc/README.pdf

doc: $(DOCSRC:$(SRCDIR)%.c=$(DOCDIR)%.md)

# run a single unit test
$(MU_TARGETS): %: $(BLDDIR)/%.out
	@echo "@ $@"
	@echo "* $*"
	@echo "< $<"
	@echo "^ $^"
	$(VGRIND) $(VOPTS) ./$<

# build a unit test's mu-header
$(MU_HEADERS): $(BLDDIR)/%.h: $(TSTDIR)/%.c
	$(SRCDIR)/mu_header.sh $< $@

# build a unit test's obj file
$(MU_OBJECTS): $(BLDDIR)/%.o: $(TSTDIR)/%.c $(BLDDIR)/%.h $(SRCDIR)/minunit.h
	$(CC) -I$(BLDDIR) -I$(SRCDIR) $(CFLAGS) -o $@ -c $<

# build a unit test runner
$(MU_RUNNERS): $(BLDDIR)/%.out: $(BLDDIR)/%.o $(BLDDIR)/lib$(LIB).so
	$(CC) -L$(BLDDIR) -Wl,-rpath,.:$(BLDDIR) $< -o $@ -l$(LIB)


# show variables, assumes a make test was done previously
echo:
	@echo "RM          = $(RM)"
	@echo "BUSTED      = $(BUSTED)"
	@echo "BOPTS       = $(BOPTS)"
	@echo
	@echo "LIB         = $(LIB)"
	@echo "TARGET      = $(TARGET)"
	@echo "VERSION     = $(VERSION)"
	@echo "FILES       = $(FILES)"
	@echo "SRCS        = $(SRCS)"
	@echo "OBJS        = $(OBJS)"
	@echo "DEPS        = $(DEPS)"
	@echo "DOCSRC      = $(DOCSRC)"
	@echo "DOCS        = $(DOCS)"
	@echo
	@echo "CTARGET     = $(CTARGET)"
	@echo "COBJS       = $(COBJS)"
	@echo "SONAME      = $(SONAME)"
	@echo "VERSION     = $(VERSION)"
	@echo "MAJ,MIN,P   = $(MAJOR),$(MINOR),$(PATCH)"
	@echo
	@echo "SRC DIR     = $(SRCDIR)"
	@echo "TEST DIR    = $(TSTDIR)"
	@echo "BUILD DIR   = $(BLDDIR)"
	@echo "INSTALL DIR = $(INSTALL_DIR)"
	@echo
	@echo "MU_SOURCES  = $(MU_SOURCES)"
	@echo "MU_TARGETS  = $(MU_TARGETS)"
	@echo "MU_HEADERS  = $(MU_HEADERS)"
	@echo "MU_OBJECTS  = $(MU_OBJECTS)"
	@echo "MU_RUNNERS  = $(MU_RUNNERS)"
	@echo -n "$(CTARGET) = "
	@objdump -p $(CTARGET) | grep -i soname
	@echo
	@echo "luarocks"
	@echo "LUA_BINDIR = $(LUA_BINDIR)"
	@echo "LUA_INCDIR = $(LUA_INCDIR)"
	@echo "LUALIB     = $(LUALIB)"
	@echo "LUA        = $(LUA)"
	@echo "PREFIX     = $(PREFIX)"
	@echo "BINDIR     = $(BINDIR)"
	@echo "LIBDIR     = $(LIBDIR)"
	@echo "LUADIR     = $(LUADIR)"
	@echo "CONFDIR    = $(CONFDIR)"
	@echo
	@echo "removables"
	@echo "$(OBJS)"
	@echo "$(DEPS)"
	@echo "$(MU_HEADERS)"
	@echo "$(MU_OBJECTS)"
	@echo "$(MU_RUNNERS)"

# update the BSD sources
bsd:
	@wget -N -P $(BSDDIR) -i $(BSDDIR)/$@.urls
	@ls -lpah $(BSDDIR)

