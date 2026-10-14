#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#define MAX_AMOUNT 4096

int hex_decode(const char *hex, unsigned char *shellcode) {
    int len = (int)strlen(hex);

    while (len > 0 && (hex[len - 1] == '\n' || hex[len - 1] == '\r')) len--;

    if (len == 0 || len % 2 != 0) {
        fprintf(stderr, "Hex string must have an even number of characters\n");
        return -1;
    } 

    int shellcode_len = len / 2;

    for (int i = 0; i < shellcode_len; i++) {
        if (sscanf(hex + 2 * i, "%2hhx", &shellcode[i]) != 1) {
            fprintf(stderr, "Invalid hex character at offset %d\n", 2 * i);
            return -1;
        }
    }

    return shellcode_len;
}

void magic_spell(unsigned char *shellcode, int len) {
    printf(".∧＿∧ \n( ･ω･｡)つ━☆・*。 \n⊂　 ノ 　　　・゜+. \nしーＪ　　　°。+ *´¨) \n 　　　　　　　　　.· ´¸.·*´¨) ¸.·*¨) \n 　　　　　　　　　　(¸.·´ (¸.·'* NOP\n");
    for (int i = 4; i < len; i += 5) {
        shellcode[i] = 0x90;
    } 
}

int main(void) {
    char hex[MAX_AMOUNT * 2];
    unsigned char shellcode[MAX_AMOUNT];

    printf("Enter shellcode as hex (no spaces, no leading 0x and max %d bytes):\n", MAX_AMOUNT);

    if (!fgets(hex, sizeof(hex), stdin)) {
        fprintf(stderr, "Failed to read input\n");
        return 1;
    }

    int len = hex_decode(hex, shellcode);
    magic_spell(shellcode, len);
   
    void *mem = mmap(NULL, MAX_AMOUNT, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
   
    memcpy(mem, shellcode, len);
    void (*func)(void) = (void (*)(void))mem;
    func();

    munmap(mem, MAX_AMOUNT);
    return 0;
}
