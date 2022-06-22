#include<stdio.h>
#include<stdlib.h>
int main(){
	setvbuf(stdin, 0LL, 2, 0LL);
	setvbuf(stdout, 0LL, 2, 0LL);
	setvbuf(stderr, 0LL, 2, 0LL);
	puts("hello");
	system("sh");
	return 0;
}
