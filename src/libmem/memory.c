// memory.c

// COMP FOR UNIX
// gcc -shared -o libmemory.so memory.c

// COMP FOR WINDOWS
// x86_64-w64-mingw32-gcc -shared -o memory.dll memory.c -Wl,--out-implib=libmemory.a


#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <sys/mman.h>
#endif

typedef struct {
    uint8_t* data;
    size_t size;
} AllocatedMemory;

AllocatedMemory* allocate_memory(size_t size) {
    AllocatedMemory* mem = malloc(sizeof(AllocatedMemory));
    if (!mem) return NULL;

#ifdef _WIN32
    mem->data = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem->data) {
        free(mem);
        return NULL;
    }
#else
    void* aligned_mem; // Temporary void*
    if (posix_memalign(&aligned_mem, sizeof(void*), size) != 0) {
        perror("posix_memalign failed");
        free(mem);
        return NULL;
    }
    mem->data = (uint8_t*)aligned_mem; // Cast to uint8_t*
#endif
    mem->size = size;
    return mem;
}


void free_memory(AllocatedMemory* mem) {
    if (mem) {
#ifdef _WIN32
        VirtualFree(mem->data, 0, MEM_RELEASE);
#else
        munmap(mem->data, mem->size);
#endif
        free(mem);
    }
}

uint8_t get_byte(const AllocatedMemory* mem, size_t index) {
    return (mem && index < mem->size) ? mem->data[index] : 0; // Ternary operator
}

void set_byte(AllocatedMemory* mem, size_t index, uint8_t value) {
    if (mem && index < mem->size) {
        mem->data[index] = value;
    }
}