# Makefile for iptable

RM=/bin/rm
BUSTED=~/.luarocks/bin/busted
BOPTS=

# project directories
SRCDIR=src
TSTDIR=src/test
BLDDIR=build
DOCDIR=doc

# versioning
MAJOR=0
MINOR=0
PATCH=1
VERSION=$(MAJOR).$(MINOR).$(PATCH)
ROCKV=1

# library
PROJ=iptable
LIB=$(PROJ).so
CLIB=libiptable.so
SONAME=$(CLIB).$(MAJOR)

# C/LUA file collections
FILES= radix.c iptable.c lua_iptable.c
SRCS=$(FILES:%.c=$(SRCDIR)/%.c)
OBJS=$(FILES:%.c=$(BLDDIR)/%.o)
DEPS=$(FILES:%.c=$(BLDDIR)/%.d)
TARGET=$(BLDDIR)/$(LIB)
COBJS=$(filter-out $(lastword $(OBJS)), $(OBJS))
CTARGET=$(BLDDIR)/$(CLIB).$(VERSION)

# Flags
# override CFLAGS+= -std=c99 -g -std=c99 -fPIC
CFLAGS=  -std=gnu99
CFLAGS+= -O2 -g -fPIC
CFLAGS+= -Wall -Wextra -Werror -pedantic

# add warnings and treat them as errors
CFLAGS+= -Wno-unknown-warning-option -Wold-style-definition
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith
CFLAGS+= -Wmissing-declarations -Wredundant-decls -Wnested-externs
CFLAGS+= -Wshadow -Wcast-qual -Wcast-align -Wwrite-strings
CFLAGS+= -Wsuggest-attribute=noreturn -Wjump-misses-init

LIBFLAG= -shared
LFLAGS=  -fPIC
SONAME=-Wl,-soname=$(CLIB).$(MAJOR)

# flag DEBUG=1
ifdef DEBUG
  CFLAGS+=-DDEBUG
  BOPTS=--defer-print
endif


# not real targets
.PHONY: clean

# donot delete intermediate/auto-generated  dependency files
.SECONDARY: $(DEPS)

# Lua library (default target)
$(TARGET): $(OBJS) $(DEPS)
	$(CC) $(LIBFLAG) $(LFLAGS) $(OBJS) -o $(TARGET)

# C libary
$(CTARGET): $(COBJS)
	$(CC) $(LIBFLAG) $(LFLAGS) $(SONAME) $(COBJS) -o $(CTARGET)
	ln -sf $(CLIB).$(VERSION) $(BLDDIR)/$(CLIB)
	ln -sf $(CLIB).$(VERSION) $(BLDDIR)/$(CLIB).$(MAJOR)

# object files
$(BLDDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -I$(SRCDIR) -c $< -o $@

# dependency files .d
$(BLDDIR)/%.d: $(SRCDIR)/%.c
	@echo "@ $@"
	@echo "* $*"
	@echo "< $<"
	@echo "^ $^"
	$(CC) -I$(SRCDIR) -MM -MQ$(BLDDIR)/$*.o -MF $@ $<
#	$(CC) -I$(SRCDIR) -MM -MQ$@ -MQ$(@:%.d=%.o) -MF $@ $<

clean:
	$(RM) $(BLDDIR)/*

# include the dependencies
-include $(DEPS)
# -----------------------------------------------------------------------
# build/radix.d build/radix.o: src/radix.c src/radix.h
# build/iptable.d build/iptable.o: src/iptable.c src/radix.h src/iptable.h
# build/lua_iptable.d build/lua_iptable.o: src/lua_iptable.c src/lua.h \
#   src/luaconf.h src/lualib.h src/lauxlib.h src/radix.h src/iptable.h \
#   src/debug.h
# -----------------------------------------------------------------------


# C/LUA unit tests
test: lua_test c_test

lua_test: $(TARGET)
	@echo "\n\n--- Lua unit tests ---\n"
	@$(BUSTED) $(BOPTS) .

# MINUT - C unit tests
MU_SOURCES=$(sort $(wildcard $(TSTDIR)/test_*.c))
MU_TARGETS=$(MU_SOURCES:$(TSTDIR)/%.c=%)
MU_HEADERS=$(MU_TARGETS:%=$(BLDDIR)/%.h)
MU_OBJECTS=$(MU_TARGETS:%=$(BLDDIR)/%.o)
MU_RUNNERS=$(MU_TARGETS:%=$(BLDDIR)/%.out)

# run all unit tests
c_test: $(CTARGET) $(MU_RUNNERS)
	@echo "\n\n--- C unit tests ---\n"
	@$(foreach runner, $(MU_RUNNERS), valgrind --leak-check=yes ./$(runner);)

# endif

# # run a single unit test
$(MU_TARGETS): %: $(BLDDIR)/%.out
	@valgrind --leak-check=yes ./$<

# # build a unit test's mu-header
$(MU_HEADERS): $(BLDDIR)/%.h: $(TSTDIR)/%.c
	$(SRCDIR)/mu_header.sh $< $@

# build a unit test's obj file
$(MU_OBJECTS): $(BLDDIR)/%.o: $(TSTDIR)/%.c $(BLDDIR)/%.h $(SRCDIR)/minunit.h
	$(CC) -I$(BLDDIR) -I$(SRCDIR) $(CFLAGS) -o $@ -c $<

# build a unit test runner
$(MU_RUNNERS): $(BLDDIR)/%.out: $(BLDDIR)/%.o $(BLDDIR)/$(CLIB)
	$(CC) -L$(BLDDIR) -Wl,-rpath,.:$(BLDDIR) $< -o $@ -l$(PROJ)


# show variables
echo:
	@echo
	@echo "RM          = $(RM)"
	@echo "BUSTED      = $(BUSTED)"
	@echo "BOPTS       = $(BOPTS)"
	@echo
	@echo "PROJ        = $(PROJ)"
	@echo "LIB         = $(LIB)"
	@echo "TARGET      = $(TARGET)"
	@echo "VERSION     = $(VERSION)"
	@echo "FILES       = $(FILES)"
	@echo "SRCS        = $(SRCS)"
	@echo "OBJS        = $(OBJS)"
	@echo "DEPS        = $(DEPS)"
	@echo
	@echo "CTARGET     = $(CTARGET)"
	@echo "CLIB        = $(CLIB)"
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
	@echo -n "$(TARGET) = "
	@objdump -p $(TARGET) | grep -i soname
	@echo -n "$(CTARGET) = "
	@objdump -p $(CTARGET) | grep -i soname

# BSD sources - update (runs unconditionally)
bsd:
	@wget -N -P $(DOCDIR)/$@ -i $(D_DOC)/$@.urls
	@ls -lpah $(DOCDIR)/$@

