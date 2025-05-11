#include "main.h"

char *convert(unsigned int num, int base){
	static char Representation[] = "0123456789ABCDEF";
	static char buffer[50];
	char* ptr;

	ptr = &buffer[49];
	*ptr = '\0';

	do{
		*--ptr = Representation[num%base];
		num /= base;
	}while(num != 0);

	return(ptr);
}

void my_sprintf(char* buf, const char* fmt, ...){
	char* traverse, *s;
	int i;

	//Initializing myprintf args
	va_list arg;
	va_start(arg, fmt);

	//start of sprintf
	for (traverse = (char*) fmt; *traverse; traverse++){
		while (*traverse != '%'){
			*buf = *traverse;
			if (!*traverse){
				break;
			}
			buf++;
			traverse++;
		}
		if (!*traverse){
			break;
		}
		traverse++;

		//Fetching and executing arguments
		switch(*traverse){

		case 'c':
			i = va_arg(arg,int);
			*buf = i;
			break;
		case 'd':
			i = va_arg(arg,int);
			if (i<0){
				i = -i;
				*buf = '-';
				buf++;
			}
			s = convert(i,10);
			while(*s){
				*buf++ = *s++;
			}
			break;
		case 'u':
			i = va_arg(arg,unsigned int);
			s = convert(i,10);
			while(*s){
				*buf++ = *s++;
			}
			break;
		case 's':
			s = va_arg(arg, char*);
			if (s) {
				while (*s) {
					*buf++ = *s++;
				}
			}
			break;
		case 'w':
			s = va_arg(arg, char*);
			if (s) {
				while (*s || *(s+1)) {
					if (!*s) {
						s++;
					}
					*buf++ = *s++;
				}
			}
			break;
		case 'x':
			i = va_arg(arg, unsigned int);
			s = convert(i,16);
			while(*s){
				*buf++ = *s++;
			}
			break;
		default:
			break;
		}
	}
	*buf = '\0';
	va_end(arg);
}