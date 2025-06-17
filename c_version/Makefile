CC=gcc
CFLAGS=-O2 -Wall
LIBS=`curl-config --libs`

all: send_wazuh_mail

send_wazuh_mail: send_wazuh_mail.c
	$(CC) $(CFLAGS) -o send_wazuh_mail send_wazuh_mail.c $(LIBS)

clean:
	rm -f send_wazuh_mail
