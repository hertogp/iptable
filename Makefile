# Makefile for iptable for C or Lua
# ---------------------|---------------------
# Lua                  | C
# ---------------------|---------------------
# make                 | make CLIB=1
# make test            | make test CLIB=1
# make install         | make install CLIB=1


RM=/bin/rm

#
# project directories
#
D_SRC=src
D_INCL=src/include
D_BIN=src/bin
D_UNIT=src/test
D_TEST=test
D_BUILD=build

#
# LIB iptable version 1, MINOR set below
#
MINOR=0.1
VERSION=1.$(MINOR)
LIB=iptable
TARGET=$(LIB).so

# make CLIB=1 builds C-library instead of Lua-library
SRCS=$(sort $(wildcard $(D_SRC)/*.c))
ifdef CLIB
	SRCS:=$(filter-out %/lua_iptable.c, $(SRCS))
	TARGET:=lib$(TARGET).$(VERSION)
endif
OBJS=$(SRCS:src/%.c=$(D_BUILD)/%.o)

CFLAGS+= -std=c99 -O2 -g -Wall -Wextra -Werror -pedantic -fPIC
CFLAGS+= -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE -D_DEFAULT_SOURCE
CFLAGS+= -Wno-unknown-warning-option -Wold-style-definition
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith
CFLAGS+= -Wmissing-declarations -Wredundant-decls -Wnested-externs
CFLAGS+= -Wshadow -Wcast-qual -Wcast-align -Wwrite-strings
CFLAGS+= -Wsuggest-attribute=noreturn -Wjump-misses-init

LFLAGS=  -fPIC -shared -Wl,-soname=$(TARGET:.$(MINOR)=)

# make <tgt> DEBUG=1
ifdef DEBUG
  DFLAGS=-DDEBUG
else
  DFLAGS=
endif

.PHONY: test clean purge
.PRECIOUS: %/.f

# create (sub)dir and marker file .f
%/.f:
	@mkdir -p $(dir $@)
	@touch $@

.SECONDEXPANSION:

#
# Default target
#
# shared object file & its symlinks
$(D_BUILD)/$(TARGET): $(OBJS)
	$(CC) $(LFLAGS) $^ -o $@
ifdef CLIB
	@ln -sf $(TARGET) $(@:.$(VERSION)=)
	@ln -sf $(TARGET) $(@:.$(MINOR)=)
endif

# object files
$(D_BUILD)/%.o: $(D_SRC)/%.c $$(@D)/.f
	$(CC) $(DFLAGS) $(CFLAGS) -I$(D_INCL) -c $< -o $@

$(LIB): $(OBJS)
	@echo "making $(@)"
	$(CC) -fPIC -shared -Wl,-soname=$(LIB).so $^ -o $(D_BUILD)/$(LIB).so

clean:
	@$(RM) -f $(D_BUILD)/* $(D_TEST)/*

purge: clean
	@rm -f $(D_BUILD)/.f $(D_TEST)/.f
	@rmdir $(D_BUILD) $(D_TEST)


dbg:
	@echo
	@echo "     TARGET : $(TARGET)"
	@echo "       SRCS : $(SRCS)"
	@echo "       OBJS : $(OBJS)"
	@echo "      Debug : ${DEBUG}"
	@echo "     DFLAGS : $(DFLAGS)"
	@echo " -----------:"
	@echo "      D_SRC : $(D_SRC)"
	@echo "     D_INCL : $(D_INCL)"
	@echo "      D_BIN : $(D_BIN)"
	@echo "     D_UNIT : $(D_UNIT)"
	@echo "     D_TEST : $(D_TEST)"
	@echo "    D_BUILD : $(D_BUILD)"
	@echo " -----------:"
	@echo " MU_SOURCES : $(MU_SOURCES)"
	@echo " MU_TARGETS : $(MU_TARGETS)"
	@echo " MU_HEADERS : $(MU_HEADERS)"
	@echo " MU_OBJECTS : $(MU_OBJECTS)"
	@echo " MU_RUNNERS : $(MU_RUNNERS)"
	@echo


#
# busted -> lua unit test_*_spec.lua files
# - lua unit tests are in src/test/lua
# - a .busted config file in project root seems to be ignored?
#

#
# BSD sources - refresh/retrieve
#
bsd:
	@wget -N -P doc/bsd -i doc/bsd.urls

ifndef CLIB
#
# BUSTED - LUA unit test
#
test:
	@busted .

else

#
# MINUT - C unit tests
#
MU_SOURCES=$(sort $(wildcard $(D_UNIT)/test_*.c))
MU_TARGETS=$(MU_SOURCES:$(D_UNIT)/%.c=%)
MU_HEADERS=$(MU_TARGETS:%=$(D_BUILD)/%_mu.h)
MU_OBJECTS=$(MU_TARGETS:%=$(D_BUILD)/%.o)
MU_RUNNERS=$(MU_TARGETS:%=$(D_TEST)/%)

# run all unit tests
test: $(MU_RUNNERS)
	@$(foreach runner, $(MU_RUNNERS), valgrind --leak-check=yes ./$(runner);)

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

endif
