all: netfilter-test

netfilter-test: netfilter-test.o
	gcc -o netfilter-test main.c -lnetfilter_queue

netfilter-test.o: main.c

clean:
	rm -f netfilter-test
	rm -f *.o
