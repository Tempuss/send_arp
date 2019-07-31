all : arp 

arp : main.o
	g++ -g -o arp main.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f arp 
	rm -f *.o

