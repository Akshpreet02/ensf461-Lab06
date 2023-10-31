#include <stddef.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include "myalloc.h"

#define PAGE_SIZE 4096
#define MIN_ALLOC_SIZE (sizeof(struct block) + 16)
#define MAX_ALLOC_SIZE (PAGE_SIZE - sizeof(struct block))

struct block {
    size_t size;
    struct block* next;
};

static struct block* head = NULL;
static void* _arena_start = NULL;
static size_t total_size = 0;

int myinit(size_t size) {
    if (size == 0 || size % PAGE_SIZE != 0 || size > MAX_ALLOC_SIZE) {
        return 0;
    }

    _arena_start = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (_arena_start == MAP_FAILED) {
        return 0;
    }

    head = _arena_start;
    head->size = size - sizeof(struct block);
    head->next = NULL;
    total_size = size;

    return 1;
}

//FUNCTION: myalloc
//INPUT: size_t size
//OUTPUT: returns a pointer to the allocated memory if successful, NULL if not
//DESCRIPTION: allocates a block of memory of at least the requested size. The
//returned pointer is guaranteed to be aligned to a 16-byte boundary. The
//returned block of memory may be larger than the requested size. The extra
//space is used to store information about the block. If the requested size is
//0, then the returned pointer is NULL. If the requested size is larger than
//the maximum size that can be allocated, then the returned pointer is NULL.
//NO USING MALLOC() IN THIS FUNCTION
void* myalloc(size_t size){
    if (size == 0 || size > MAX_ALLOC_SIZE) {
        return NULL;
    }

    // Align size to 16-byte boundary
    size_t aligned_size = (size + 15) & ~15;

    // Find first block that is large enough
    struct block* curr = head;
    struct block* prev = NULL;
    while (curr != NULL && curr->size < aligned_size) {
        prev = curr;
        curr = curr->next;
    }

    if (curr == NULL) {
        // No block is large enough, allocate a new one
        size_t block_size = aligned_size + sizeof(struct block);
        if (block_size < MIN_ALLOC_SIZE) {
            block_size = MIN_ALLOC_SIZE;
        }

        void* block = mmap(NULL, block_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (block == MAP_FAILED) {
            return NULL;
        }

        struct block* new_block = block;
        new_block->size = block_size - sizeof(struct block);
        new_block->next = NULL;

        if (prev == NULL) {
            head = new_block;
        } else {
            prev->next = new_block;
        }

        return (void*) ((char*) new_block + sizeof(struct block));
    } else {
        // Split block if it is large enough
        size_t remaining_size = curr->size - aligned_size;
        if (remaining_size >= MIN_ALLOC_SIZE) {
            struct block* new_block = (struct block*) ((char*) curr + sizeof(struct block) + aligned_size);
            new_block->size = remaining_size - sizeof(struct block);
            new_block->next = curr->next;

            curr->size = aligned_size;

            if (prev == NULL) {
                head = new_block;
            } else {
                prev->next = new_block;
            }
        }

        return (void*) ((char*) curr + sizeof(struct block));
    }
}


//FUNCTION: myfree
//INPUT: void* ptr
//OUTPUT: none
//DESCRIPTION: frees a block of memory that was previously allocated using
//myalloc(). If the ptr argument is NULL, then the function does nothing. If
//the ptr argument is not NULL, but it was not returned by a previous call to
//myalloc(), then the function does nothing. If the ptr argument is not NULL
//and it was returned by a previous call to myalloc(), then the function frees
//the block of memory and makes it available for future allocations.
//NO USING MALLOC() IN THIS FUNCTION
void myfree(void* ptr){
    if (ptr == NULL) {
        return;
    }

    struct block* curr = (struct block*) ((char*) ptr - sizeof(struct block));
    if (curr < head || curr >= (struct block*) ((char*) _arena_start + total_size)) {
        return;
    }

    struct block* prev = NULL;
    struct block* next = head;
    while (next != NULL && next < curr) {
        prev = next;
        next = next->next;
    }

    if (prev == NULL) {
        head = curr;
    } else {
        prev->next = curr;
    }

    curr->next = next;

    // Merge with next block if adjacent
    if (next != NULL && (char*) curr + sizeof(struct block) + curr->size == (char*) next) {
        curr->size += sizeof(struct block) + next->size;
        curr->next = next->next;
    }

    // Merge with previous block if adjacent
    if (prev != NULL && (char*) prev + sizeof(struct block) + prev->size == (char*) curr) {
        prev->size += sizeof(struct block) + curr->size;
        prev->next = curr->next;
    }
}


//FUNCTION: mydestroy
//INPUT: none
//OUTPUT: returns 1 if successful, 0 if not
//DESCRIPTION: destroys the memory allocator. Any existing allocated memory
//blocks are freed. After this function is called, any future calls to myalloc()
//or myfree() will fail. If the function is successful, then it returns 1. If
//the function fails, then it returns 0.
//NO USING MALLOC() IN THIS FUNCTION
int mydestroy(){
    struct block* curr = head;
    while (curr != NULL) {
        struct block* next = curr->next;
        munmap(curr, sizeof(struct block) + curr->size);
        curr = next;
    }

    head = NULL;
    _arena_start = NULL;
    total_size = 0;

    return 1;
}
