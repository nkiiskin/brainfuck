CC=gcc
CFLAGS=-c -Wall
LDFLAGS=
SOURCES=pbfc.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=pbfc

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f pbfc.o pbfc *~



