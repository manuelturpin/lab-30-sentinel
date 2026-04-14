/* SAFE: Properly secured C code patterns
 * These should NOT trigger detection patterns
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* SAFE: Using snprintf instead of sprintf */
void safe_format(const char *user, const char *msg) {
    char output[128];
    snprintf(output, sizeof(output), "User %s said: %s", user, msg);
    puts(output);
}

/* SAFE: Using strncpy with bounds */
void safe_copy(const char *input) {
    char buffer[64];
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    printf("Copied: %s\n", buffer);
}

/* SAFE: Using fgets instead of gets */
void safe_input() {
    char name[32];
    fgets(name, sizeof(name), stdin);
    printf("Hello, %s\n", name);
}

/* SAFE: Bounds-checked array access */
void safe_array(int index, int value) {
    int arr[10];
    if (index >= 0 && index < 10) {
        arr[index] = value;
    }
}

/* SAFE: Proper memory management — no use-after-free */
void safe_memory() {
    char *buf = (char *)malloc(256);
    if (buf == NULL) return;
    strncpy(buf, "data", 256);
    printf("Data: %s\n", buf);
    free(buf);
    buf = NULL;  /* Prevent dangling pointer */
}

/* SAFE: Using smart pointers equivalent pattern */
struct SafeNode {
    int value;
    struct SafeNode *next;
};

void safe_node_usage() {
    struct SafeNode *node = malloc(sizeof(struct SafeNode));
    if (node == NULL) return;
    node->value = 42;
    node->next = NULL;
    int val = node->value;
    free(node);
    node = NULL;
    /* No access after free */
    (void)val;
}

/* SAFE: strncat with bounds */
void safe_concat(const char *a, const char *b) {
    char result[64];
    result[0] = '\0';
    strncat(result, a, sizeof(result) - 1);
    strncat(result, b, sizeof(result) - strlen(result) - 1);
}

/* SAFE: memcpy with bounds check */
void safe_memcpy(void *src, size_t len) {
    char dest[256];
    if (len > sizeof(dest)) len = sizeof(dest);
    memcpy(dest, src, len);
}
