# Makefile for iptable

PROJ=ipt
cfiles=$(sort $(wildcard test_*.c))
hfiles=$(cfiles:.c=_mu.h)
ofiles=$(cfiles:.c=.o)
tests=$(cfiles:.c=)
runners=$(tests:%=run_%)

CFLAGS+=	-std=c99 -O2 -g -Wall -Wextra -Werror
CFLAGS+=	-D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE -D_DEFAULT_SOURCE
CFLAGS+=	-fPIC
# CFLAGS+=	-pedantic  # will fail on radix.c's log macro and rn_delete()
# CFLAGS+=	-Wno-unknown-warning-option  # clang option, not gcc?
CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith
CFLAGS+=	-Wmissing-declarations -Wredundant-decls -Wnested-externs
CFLAGS+=	-Wshadow -Wcast-qual -Wcast-align -Wwrite-strings
CFLAGS+=	-Wold-style-definition
CFLAGS+=	-Wsuggest-attribute=noreturn -Wjump-misses-init
LDFLAGS=    #-fPIC -shared

all: ${PROJ} test

.PHONY: all clean test

${PROJ}.o: iptable.c
	$(CC) $(CFLAGS) -c iptable.c -o $@

radix.so:
	$(CC) $(CFLAGS) -o radix.so -c radix.c

radix.o:
	$(CC) $(CFLAGS) -o radix.o -c radix.c

${PROJ}: radix.o radix.so iptable.c ${PROJ}.o
	$(CC) $(CFLAGS) -o ${PROJ}.o -c iptable.c
	$(CC) $(LDFLAGS) -o ${PROJ} radix.so ${PROJ}.o

clean:
	rm -f *.o *.so stdout.txt ${PROJ} *_mu.h run_test_*
#
# MINUNIT
#
dbg:
	@echo "cfiles  " $(cfiles)
	@echo "hfiles  " $(hfiles)
	@echo "ofiles  " $(hfiles)
	@echo "tests   " $(tests)
	@echo "runners " $(runners)
	@echo "PROJ    " $(PROJ)
	@echo "LIBS    " $(LIBS)
	@echo "OBJS    " $(OBJS)

test: $(runners)
	@$(foreach runner, $(runners), valgrind --leak-check=yes ./$(runner);)

$(tests): %:run_%
	@valgrind --leak-check=yes ./$<

$(hfiles): %_mu.h: %.c
	./mu_header $<

$(ofiles): %.o: %.c %_mu.h
	${CC} ${CFLAGS} -o $@ -c $<
	@ln -fs $@ run_$@

$(runners): run_%: %.o %_mu.h minunit.h ${PROJ}.o radix.so
	strip -N main ${PROJ}.o -o ${PROJ}_stripped.o
	${CC} ${CFLAGS} $@.o ${PROJ}_stripped.o radix.so -o $@


