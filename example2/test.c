#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>
#define KEY_LEN 8
#define PASS_LEN 32
//Key is ABCDEFG\0
char *ipass = "\x23\x89\xf2\xc2\x6d\x3e\xc7\xb2\0";
char *pass="\x62\xcb\xb1\x86\x28\x78\x80\xb2\x23\x89\xf2\xc2\x6d\x3e\xc7\xb2\x23\x89\xf2\xc2\x6d\x3e\xc7\xb2\x23\x89\xf2\xc2\x6d\x3e\xc7\xb2";

int obfuscate ( char *d, char *s, int n){
	int i;
	for (i = 0; i < n; i++){
		d[i] ^= s[i % KEY_LEN];
	}
}

void gen_pass(char *p){
	char *p1 = p + PASS_LEN;
	while(p1 != p){
		write (1, (--p1), 1);
	}
}
ssize_t my_getpass (char *lineptr, size_t n, int fd){
	int nread;
	nread = read(1,lineptr,n);
	return nread;
}
int my_print(char *buf){
	return write(1,buf,strlen(buf));
}

	
int main(int argc, char *argv[]){
	char *p;
	size_t len, l, i;
	
	my_print("\nBegin!\n");
	my_print("Password:\n");
	len = PASS_LEN;
	p = malloc(len);
	l = my_getpass(p,len,0);
	p[l-1] = 0;
	obfuscate(p,ipass,PASS_LEN);
	my_print("Checking\n");
	if(strncmp(p,pass,PASS_LEN) == 0){
		my_print("\nWin!\n");
	}
	else {
		my_print("\nFail!\n");
	}
	return 0;
}
