# Makefile for libipt.so
MAJOR=1
MINOR=0.1
VERSION=$(MAJOR).$(MINOR)
TGT=libipt.so.$(VERSION)

SDIR=src
UDIR=src/tst
TDIR=tst
BDIR=bld
SUBDIRS= $(BDIR) $(TDIR)

RM=/bin/rm
SRCS=$(sort $(wildcard src/*.c))
OBJS=$(SRCS:src/%.c=bld/%.o)

CFLAGS+= -std=c99 -O2 -g -Wall -Wextra -Werror -pedantic -fPIC
CFLAGS+= -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE -D_DEFAULT_SOURCE
CFLAGS+= -Wno-unknown-warning-option -Wold-style-definition
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith
CFLAGS+= -Wmissing-declarations -Wredundant-decls -Wnested-externs
CFLAGS+= -Wshadow -Wcast-qual -Wcast-align -Wwrite-strings
CFLAGS+= -Wsuggest-attribute=noreturn -Wjump-misses-init

LFLAGS=  -fPIC -shared -Wl,-soname=$(TGT:.$(MINOR)=)

.PHONY: test clean
.PRECIOUS: %/.f

# create (sub)dir and marker file .f
%/.f:
	@mkdir -p $(dir $@)
	@touch $@

.SECONDEXPANSION:

$(BDIR)/%.o: $(SDIR)/%.c $$(@D)/.f
	$(CC) $(CFLAGS) -c $< -o $@

# build libipt.so.VERSION & its symlinks
$(BDIR)/$(TGT): $(OBJS)
	$(CC) $(LFLAGS) $^ -o $@
	@ln -sf $(TGT) $(@:.$(VERSION)=)
	@ln -sf $(TGT) $(@:.$(MINOR)=)

#
# MINUT
#
MU_C=$(sort $(wildcard src/tst/test_*.c))
MU_T=$(MU_C:src/tst/%.c=%)
MU_H=$(MU_T:%=bld/%_mu.h)
MU_O=$(MU_T:%=bld/%.o)
MU_R=$(MU_T:%=tst/%)

# run all unit tests
test: $(MU_R)
	@$(foreach runner, $(MU_R), valgrind --leak-check=yes ./$(runner);)

# run a single unit test
$(MU_T): %: $(TDIR)/%
	@valgrind --leak-check=yes ./$<

# build a unit test's mu-header
$(MU_H): $(BDIR)/%_mu.h: $(UDIR)/%.c $$(@D)/.f
	$(SDIR)/mu_header.sh $< $@

# build a unit test's obj file
$(MU_O): $(BDIR)/%.o: $(UDIR)/%.c $(BDIR)/%_mu.h $(SDIR)/minunit.h
	$(CC) -I$(BDIR) -I$(SDIR) $(CFLAGS) -o $@ -c $<

# build a unit test runner
$(MU_R): $(TDIR)/%: $(BDIR)/%.o $(BDIR)/$(TGT) $$(@D)/.f
	$(CC) -L$(BDIR) -Wl,-rpath,.:$(BDIR) $< -o $@ -lipt

clean:
	@$(RM) -f bld/* tst/*
