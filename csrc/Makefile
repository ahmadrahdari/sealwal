# builds the LM-OTS / LMS core used by sealwal/lms.py (needs OpenSSL headers)
CC ?= gcc
CFLAGS ?= -O2 -Wall -Wno-deprecated-declarations

../sealwal/_lmots.so: lmots.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $< -lcrypto

clean:
	rm -f ../sealwal/_lmots.so

.PHONY: clean
