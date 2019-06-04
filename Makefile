# Makefile for libipt.so

# LIB iptable version 1, MINOR set below

MINOR=0.1
VERSION=1.$(MINOR)
LIB=iptable
TARGET=lib$(LIB).so.$(VERSION)

# LIB generic

SRC_DIR=src
INC_DIR=src/include
BIN_DIR=src/bin
UNIT_DIR=src/test
TEST_DIR=test
BUILD_DIR=build

RM=/bin/rm
SRCS=$(sort $(wildcard $(SRC_DIR)/*.c))
OBJS=$(SRCS:src/%.c=$(BUILD_DIR)/%.o)

CFLAGS+= -std=c99 -O2 -g -Wall -Wextra -Werror -pedantic -fPIC
CFLAGS+= -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE -D_DEFAULT_SOURCE
CFLAGS+= -Wno-unknown-warning-option -Wold-style-definition
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith
CFLAGS+= -Wmissing-declarations -Wredundant-decls -Wnested-externs
CFLAGS+= -Wshadow -Wcast-qual -Wcast-align -Wwrite-strings
CFLAGS+= -Wsuggest-attribute=noreturn -Wjump-misses-init

LFLAGS=  -fPIC -shared -Wl,-soname=$(TARGET:.$(MINOR)=)

# make <tgt> DEBUG=1
ifeq (${DEBUG}, 1)
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

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $$(@D)/.f
	$(CC) $(DFLAGS) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

# build libiptable.VERSION & its symlinks
$(BUILD_DIR)/$(TARGET): $(OBJS)
	$(CC) $(LFLAGS) $^ -o $@
	@ln -sf $(TARGET) $(@:.$(VERSION)=)
	@ln -sf $(TARGET) $(@:.$(MINOR)=)


dbg:
	@echo "Debug is ${DEBUG}, and DBG is $(DBG); see?"
#
# busted -> lua unit test_*_spec.lua files
# - lua unit tests are in src/test/lua
# - a .busted config file in project root seems to be ignored?
#

busted:
	@busted .
#
# BSD sources
#

LUAOBJS = $(BUILD_DIR)/iptable.o $(BUILD_DIR)/radix.o $(BUILD_DIR)/lua_iptable.o
lua: $(BUILD_DIR)/iptable.o $(BUILD_DIR)/radix.o $(SRC_DIR)/lua/lua_iptable.c
	$(CC) $(DFLAGS) $(CFLAGS) -I$(INC_DIR) -c src/lua/lua_iptable.c -o $(BUILD_DIR)/lua_iptable.o
	$(CC) -fPIC -shared -Wl,-soname=iptable.so $(LUAOBJS) -o $(BUILD_DIR)/iptable.so

bsd:
	@wget -N -P doc/bsd -i doc/bsd.urls

#
# MINUT
#
MU_SOURCES=$(sort $(wildcard $(UNIT_DIR)/test_*.c))
MU_TARGETS=$(MU_SOURCES:$(UNIT_DIR)/%.c=%)
MU_HEADERS=$(MU_TARGETS:%=$(BUILD_DIR)/%_mu.h)
MU_OBJECTS=$(MU_TARGETS:%=$(BUILD_DIR)/%.o)
MU_RUNNERS=$(MU_TARGETS:%=$(TEST_DIR)/%)

# run all unit tests
test: $(MU_RUNNERS)
	@$(foreach runner, $(MU_RUNNERS), valgrind --leak-check=yes ./$(runner);)

# run a single unit test
$(MU_TARGETS): %: $(TEST_DIR)/%
	@valgrind --leak-check=yes ./$<

# build a unit test's mu-header
$(MU_HEADERS): $(BUILD_DIR)/%_mu.h: $(UNIT_DIR)/%.c $$(@D)/.f
	$(BIN_DIR)/mu_header.sh $< $@

# build a unit test's obj file
$(MU_OBJECTS): $(BUILD_DIR)/%.o: $(UNIT_DIR)/%.c $(BUILD_DIR)/%_mu.h $(INC_DIR)/minunit.h
	$(CC) -I$(BUILD_DIR) -I$(INC_DIR) $(CFLAGS) -o $@ -c $<

# build a unit test runner
$(MU_RUNNERS): $(TEST_DIR)/%: $(BUILD_DIR)/%.o $(BUILD_DIR)/$(TARGET) $$(@D)/.f
	$(CC) -L$(BUILD_DIR) -Wl,-rpath,.:$(BUILD_DIR) $< -o $@ -l$(LIB)

clean:
	@$(RM) -f $(BUILD_DIR)/* $(TEST_DIR)/*

purge: clean
	@rm -f $(BUILD_DIR)/.f $(TEST_DIR)/.f
	@rmdir $(BUILD_DIR) $(TEST_DIR)
