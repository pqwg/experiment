# # This Makefile can be used with GNU Make or BSD Make

# LIB=libml-kem-512_clean.a
# HEADERS=api.h cbd.h indcpa.h kem.h ntt.h params.h poly.h polyvec.h reduce.h symmetric.h verify.h 
# OBJECTS=cbd.o indcpa.o kem.o ntt.o poly.o polyvec.o reduce.o symmetric-shake.o verify.o 

# CFLAGS=-O3 -Wall -Wextra -Wpedantic -Werror -Wmissing-prototypes -Wredundant-decls -std=c99 -Icommon $(EXTRAFLAGS)

# all: $(LIB)

# %.o: %.c $(HEADERS)
# 	$(CC) $(CFLAGS) -c -o $@ $<

# $(LIB): $(OBJECTS)
# 	$(AR) -r $@ $(OBJECTS)

# clean:
# 	$(RM) $(OBJECTS)
# 	$(RM) $(LIB)

CC=/usr/bin/gcc
# CFLAGS=-O3 -Wall -Wextra -Wpedantic -Werror -Wmissing-prototypes -Wredundant-decls -std=c99 -Icommon $(EXTRAFLAGS)
CFLAGS=-O3 -Wall -Wextra -std=c99 -Icommon $(EXTRAFLAGS)

LDFLAGS=

SOURCES= cbd.c indcpa.c kem.c ntt.c poly.c polyvec.c reduce.c verify.c symmetric-shake.c randombytes.c common/fips202.c
HEADERS= cbd.h api.h indcpa.h kem.h ntt.h params.h poly.h polyvec.h reduce.h symmetric.h verify.h randombytes.h

speed: test_speed.c $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -o $@ test_speed.c $(SOURCES) $(LDFLAGS)

.PHONY: clean

clean:
	-rm test
