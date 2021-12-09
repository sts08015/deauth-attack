CC = g++
LDLIBS = -lpcap

all: deauth-attack

deauth-attack: mac.o main.o
	$(CC) $^ -o $@ $(LDLIBS)

clean:
	@rm -f *o deauth-attack