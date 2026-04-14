/* VULNERABLE: Memory Safety Issues
 * CWE-416 (Use After Free), CWE-119 (Buffer Overflow), CWE-787 (Out-of-bounds Write)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* CWE-416: Use-after-free */
void use_after_free_example() {
    char *buf = (char *)malloc(256);
    strcpy(buf, "sensitive data");
    free(buf);
    /* Use after free — buf is dangling */
    printf("Data: %s\n", buf);
    buf[0] = 'x';
}

/* CWE-416: Use-after-free with struct */
struct Node {
    int value;
    struct Node *next;
};

void dangling_pointer() {
    struct Node *node = malloc(sizeof(struct Node));
    node->value = 42;
    free(node);
    /* Dangling pointer access */
    int val = node->value;
    node->next = NULL;
}

/* CWE-119: Buffer overflow — strcpy without bounds check */
void buffer_overflow(const char *input) {
    char buffer[64];
    strcpy(buffer, input);
    printf("Copied: %s\n", buffer);
}

/* CWE-119: Buffer overflow — gets (always unsafe) */
void unsafe_input() {
    char name[32];
    gets(name);
    printf("Hello, %s\n", name);
}

/* CWE-787: Out-of-bounds write — sprintf without bounds */
void format_string_overflow(const char *user, const char *msg) {
    char output[128];
    sprintf(output, "User %s said: %s at %s", user, msg, __TIME__);
    puts(output);
}

/* CWE-787: Stack-based buffer overflow */
void stack_overflow(int index, int value) {
    int arr[10];
    /* No bounds check */
    arr[index] = value;
}

/* CWE-416: Objective-C style — __unsafe_unretained */
/* __unsafe_unretained id delegate; */
/* This would be in .m files but shown for pattern matching */

/* CWE-119: strcat without bounds */
void concat_overflow(const char *a, const char *b) {
    char result[64];
    strcpy(result, a);
    strcat(result, b);
}

/* CWE-787: memcpy with unchecked size */
void unchecked_memcpy(void *src, size_t len) {
    char dest[256];
    memcpy(dest, src, len);
}
