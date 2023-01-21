
CC = gcc
CFLAGS = -Wall -g -fPIC

all: sniffer spoofer sas
	clear
	rm log.txt

sniffer: sniffer.o
	$(CC) $(CFLAGS) $^ -o $@ -lpcap
spoofer: spoofer.o
	$(CC) $(CFLAGS) $^ -o $@ -lpcap
sas: sas.o
	$(CC) $(CFLAGS) $^ -o $@ -lpcap

#------- o files-------
%.o:%.c
	$(CC) $(CFLAGS) -c $^ -o $@	
#------------------------------

clean:
	rm  *.o sniffer spoofer sas