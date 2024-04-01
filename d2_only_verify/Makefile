CC ?= /usr/bin/cc
# CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
#   -Wshadow -Wvla -Wpointer-arith -O3 -march=native -mtune=native -g -Wno-overlength-strings -O0
# --stack=size
NISTFLAGS += -Wno-unused-result -O3 -g
SOURCES = sign.c packing.c polyvec.c poly.c ntt.c reduce.c rounding.c
HEADERS = config.h sign.h packing.h polyvec.h poly.h ntt.h \
  reduce.h rounding.h symmetric.h 
KECCAK_SOURCES = $(SOURCES) fips202.c symmetric-shake.c
KECCAK_HEADERS = $(HEADERS) fips202.h


.PHONY: all clean

all: main.out 

main.out : main.c  $(KECCAK_SOURCES) \
  $(KECCAK_HEADERS)
	@$(CC) $(NISTFLAGS) -o $@ $<  $(KECCAK_SOURCES)

clean:
	@rm -f main.out 
