#include "main.h"

#pragma optimize("", off)
void my_memset(void* dest, int val, size_t len){
    register unsigned char* s = (unsigned char*)dest;

    while (len-- > 0){
        *s++ = val;
    }  
}

void my_memcpy(char* dest, const char* src, unsigned int len){

    while (len-- > 0){
        *dest++ = *src++;
    }
}

size_t my_strlen(const char* str) {
    register const char* s;
    for (s = str; *s; ++s);
    return(s - str);
}

char* my_strcat(char* dest, const char* source) {

    char* ptr = dest + my_strlen(dest);
    while (*source) {
        *ptr++ = *source++;
    }
    *ptr = '\0';
    return dest;
}

int my_strcmp(const char* s1, const char* s2)
{

    while (*s1 == *s2++)
        if (*s1++ == 0)
            return (0);
    return (*(unsigned char*)s1 - *(unsigned char*)--s2);
}

char* my_strstr(const char* str, const char* substring) {

    const char* a = str, * b = substring;
    for (;;) {
        if (!*b) return (char*)str;
        if (!*a) return NULL;
        if (*a++ != *b++) { a = ++str; b = substring; }
    }
}

/*char* my_strstr(const char* str1, const char* str2) {
    char* cp = (char *)str1;
    char* s1;
    char* s2;

    if ( !*str2 ){
        return((char *)str1);
    }
    while (*cp){
        s1 = cp;
        s2 = (char *) str2;
        while ( *s2 && !(*s1 - *s2) ){
            s1++, s2++;
        }
        if (!*s2){
            return(cp);
        }
        cp++;
    }
    return(NULL);
}

char* my_strstr(const char* str, const char* substring) {
    
    const char* a = str, * b = substring;
    for (;;) {
        if (!*b) return (char*)str;
        if (!*a) return NULL;
        if (*a++ != *b++) { a = ++str; b = substring; }
    }
}*/

/*HANDLE my_getprocessheap()
{
    __asm
    {
        mov eax, fs: [0x30]
        mov eax, [eax + 0x18]
    }
}*/

void* my_heapalloc(size_t Size) {
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);
	//return HeapAlloc(my_getprocessheap(), 0x00000008, Size);
}

void my_heapfree(void* mem){

	if (mem) {
        HeapFree(GetProcessHeap(), 0, mem);
    }
}