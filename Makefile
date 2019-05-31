# Makefile for libipt.so
MAJOR=1
MINOR=0.1
VERSION=$(MAJOR).$(MINOR)
TARGET=libipt.so.$(VERSION)

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

.PHONY: test clean
.PRECIOUS: %/.f

# create (sub)dir and marker file .f
%/.f:
	@mkdir -p $(dir $@)
	@touch $@

.SECONDEXPANSION:

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $$(@D)/.f
	$(CC) $(CFLAGS) -c $< -o $@

# build libipt.so.VERSION & its symlinks
$(BUILD_DIR)/$(TARGET): $(OBJS)
	$(CC) $(LFLAGS) $^ -o $@
	@ln -sf $(TARGET) $(@:.$(VERSION)=)
	@ln -sf $(TARGET) $(@:.$(MINOR)=)

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
$(MU_OBJECTS): $(BUILD_DIR)/%.o: $(UNIT_DIR)/%.c $(BUILD_DIR)/%_mu.h $(SRC_DIR)/minunit.h
	$(CC) -I$(BUILD_DIR) -I$(SRC_DIR) $(CFLAGS) -o $@ -c $<

# build a unit test runner
$(MU_RUNNERS): $(TEST_DIR)/%: $(BUILD_DIR)/%.o $(BUILD_DIR)/$(TARGET) $$(@D)/.f
	$(CC) -L$(BUILD_DIR) -Wl,-rpath,.:$(BUILD_DIR) $< -o $@ -lipt

clean:
	@$(RM) -f $(BUILD_DIR)/* $(TEST_DIR)/*
