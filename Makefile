cpuleash:	cpuleash.c
	gcc -D DEBUG=0 cpuleash.c -lm -o cpuleash -Wall -Wextra 
debug:	cpuleash.c
	gcc -D DEBUG=1 -g cpuleash.c -lm -o cpuleash -Wall -Wextra

clean:
	rm -f *~ cpuleash


