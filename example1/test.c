#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(){
	char s[100];
	puts("Testing Dyn Sym Engine");
	printf("Buffer space %lu\n",sizeof(s));
	read(0,&s,sizeof(s)-1);
	if(s[0] == 'A'){
		if(s[1] == 'B'){
			if(s[2] == 'C'){
				if(s[3] == 'D'){
					puts("You did it!");
					return 0;
				}
			}
		}
	}
	puts("Fail!");
	return -1;
}
