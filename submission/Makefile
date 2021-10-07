##
# Password Cracker
#
# @file
# @version 0.1
CC = gcc

CFLAGS = -pthread -Wall -std=c11


LFLAGS = -lssl -lcrypto -pthread -lrt
OBJECTS = password-cracker.o hashmap.o base64.o thpool.o

SUBMISSION_FILES = dictionary-preprocessed.txt dictionary-hash.txt *.h *.c *.py Makefile

all: password-cracker


password-cracker: $(OBJECTS)
	$(CC) -o $@ $^ $(LFLAGS)

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

.PHONY: submission clean preprocess run check

run: password-cracker
	-./password-cracker

preprocess: check
	-./preprocess.py
check:
    @echo -n "Are you sure? [y/N] " && read ans && [ $${ans:-N} = y ]

clean:
	-rm -f *.o password-cracker

submission:
	-rm -f submission/*
	-cp $(SUBMISSION_FILES) submission
	-tar zcvf submission.tar.gz submission
	-wc -l dict*.txt
	-ls -lh submission.tar.gz
# end
