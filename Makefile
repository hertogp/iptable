# Makefile for iptable for C or Lua
#
# Lua                  | C
# ---------------------|--------------------
# make                 | make CLIB=1
# make test            | make CLIB=1 test
# make install         | TODO: make CLIB=1 install
# ------------------------------------------
# - for debugging mode, add DEBUG=1 flag
#
# See
# - http://make.mad-scientist.net/papers/advanced-auto-dependency-generation/#tldr

RM=/bin/rm
BUSTED=~/.luarocks/bin/busted
BOPTS=

# LUA directories
LUA_VER=5.3
LUA_DIR=/usr/local
LUA_LIBDIR=$(LUA_DIR)/lib/lua/$(LUA_VER)

# project directories
D_DOC=doc
D_SRC=src
D_INCL=src/include
D_BIN=src/bin
D_UNIT=src/test
D_TEST=test
D_BUILD=build
# TODO: create proper rockspec for this
D_INSTALL=~/.luarocks/lib/lua/5.3

# C-LIB iptable version 1.0.x
MINOR=0.1
VERSION=1.$(MINOR)
LIB=iptable
TARGET=$(LIB).so

# File collections
SRCS=$(sort $(wildcard $(D_SRC)/*.c))
ifdef CLIB
	SRCS:=$(filter-out %/lua_iptable.c, $(SRCS))
	TARGET:=lib$(TARGET).$(VERSION)
endif
OBJS=$(SRCS:$(D_SRC)/%.c=$(D_BUILD)/%.o)
DEPS=$(OBJS:%.o=%.d)

# Flags
# override CFLAGS+= -std=c99 -g -std=c99 -fPIC
CFLAGS=  -std=gnu99 -O2 -g -fPIC
#CFLAGS+= -D_POSIX_C_SOURCE=200810L  # <-- too old?

#CFLAGS+= -D_GNU_SOURCE
#CFLAGS+= -D_DEFAULT_SOURCE

# add warnings and treat them as errors
CFLAGS+= -Wall -Wextra -Werror -pedantic
CFLAGS+= -Wno-unknown-warning-option -Wold-style-definition
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith
CFLAGS+= -Wmissing-declarations -Wredundant-decls -Wnested-externs
CFLAGS+= -Wshadow -Wcast-qual -Wcast-align -Wwrite-strings
CFLAGS+= -Wsuggest-attribute=noreturn -Wjump-misses-init

LFLAGS=  -shared -fPIC -Wl,-soname=$(TARGET:.$(MINOR)=)
LIBFLAG= -shared

# flag DEBUG=1
ifdef DEBUG
  CFLAGS+=-DDEBUG
  BOPTS=--defer-print
endif

.PHONY: test clean purge
.PRECIOUS: %/.f

# create (sub)dir and the precious file-markers .f
%/.f:
	@mkdir -p $(dir $@)
	@touch $@

.SECONDEXPANSION:

# Default target: shared object file & its symlinks (if CLIB)
$(D_BUILD)/$(TARGET): $(OBJS) $(DEPS)
	$(CC) $(LIBFLAG) $(LFLAGS) $(OBJS) -o $@
ifdef CLIB
	@ln -sf $(TARGET) $(@:.$(VERSION)=)
	@ln -sf $(TARGET) $(@:.$(MINOR)=)
endif

# object files
$(D_BUILD)/%.o: $(D_SRC)/%.c $$(@D)/.f
	$(CC) $(CFLAGS) -I$(D_INCL) -c $< -o $@

# dependency files .d : 
$(D_BUILD)/%.d: $(D_SRC)/%.c
	$(CC) -I$(D_INCL) -MM -MQ$(D_BUILD)/$*.o -MQ$(D_BUILD)/$*.d -MF $@ $<

# include the dependencies
include $(wildcard $(D_BUILD)/*.d)


# install TODO: make proper rockspec for this.
install: $(D_BUILD)/$(TARGET)
	@echo $(D_BUILD)/$(TARGET) $(INST_LIBDIR)
	@echo mkdir -p $(INST_LIBDIR)
	@echo cp $(D_BUILD)/$(TARGET) $(INST_LIBDIR)


clean:
	@$(RM) -f $(D_BUILD)/* $(D_TEST)/*

purge: clean
	@rm -f $(D_BUILD)/.f $(D_TEST)/.f
	@rmdir $(D_BUILD) $(D_TEST)


# show variables
vars:
	@echo
	@echo "     TARGET : $(TARGET)"
	@echo "       SRCS : $(SRCS)"
	@echo "       OBJS : $(OBJS)"
	@echo "       DEPS : $(DEPS)"
	@echo " -----------:"
	@echo "      D_SRC : $(D_SRC)"
	@echo "     D_INCL : $(D_INCL)"
	@echo "      D_BIN : $(D_BIN)"
	@echo "     D_UNIT : $(D_UNIT)"
	@echo "     D_TEST : $(D_TEST)"
	@echo "    D_BUILD : $(D_BUILD)"
	@echo "   D_INSTALL: $(D_INSTALL)"
	@echo " -----------:"
ifdef CLIB
	@echo " MU_SOURCES : $(MU_SOURCES)"
	@echo " MU_TARGETS : $(MU_TARGETS)"
	@echo " MU_HEADERS : $(MU_HEADERS)"
	@echo " MU_OBJECTS : $(MU_OBJECTS)"
	@echo " MU_RUNNERS : $(MU_RUNNERS)"
	@echo
endif

# BSD sources - update (runs unconditionally)
bsd:
	@wget -N -P $(D_DOC)/$@ -i $(D_DOC)/$@.urls
	@ls -lpah $(D_DOC)/$@

ifndef CLIB

# BUSTED - LUA unit test
test:
	@$(BUSTED) $(BOPTS) .

else

# MINUT - C unit tests
MU_SOURCES=$(sort $(wildcard $(D_UNIT)/test_*.c))
MU_TARGETS=$(MU_SOURCES:$(D_UNIT)/%.c=%)
MU_HEADERS=$(MU_TARGETS:%=$(D_BUILD)/%_mu.h)
MU_OBJECTS=$(MU_TARGETS:%=$(D_BUILD)/%.o)
MU_RUNNERS=$(MU_TARGETS:%=$(D_TEST)/%)

# run all unit tests
test: $(MU_RUNNERS)
	@$(foreach runner, $(MU_RUNNERS), valgrind --leak-check=yes ./$(runner);)

endif

# run a single unit test
$(MU_TARGETS): %: $(D_TEST)/%
	@valgrind --leak-check=yes ./$<

# build a unit test's mu-header
$(MU_HEADERS): $(D_BUILD)/%_mu.h: $(D_UNIT)/%.c $$(@D)/.f
	$(D_BIN)/mu_header.sh $< $@

# build a unit test's obj file
$(MU_OBJECTS): $(D_BUILD)/%.o: $(D_UNIT)/%.c $(D_BUILD)/%_mu.h $(D_INCL)/minunit.h
	$(CC) -I$(D_BUILD) -I$(D_INCL) $(CFLAGS) -o $@ -c $<

# build a unit test runner
$(MU_RUNNERS): $(D_TEST)/%: $(D_BUILD)/%.o $(D_BUILD)/$(TARGET) $$(@D)/.f
	$(CC) -L$(D_BUILD) -Wl,-rpath,.:$(D_BUILD) $< -o $@ -l$(LIB)
