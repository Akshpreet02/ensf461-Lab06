#include <stddef.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "myalloc.h"

#define MAX_ARENA_SIZE (0x7FFFFFFF) // Adjust the definition of MAX_ARENA_SIZE

#define ALIGN(size) (((size) + (sizeof(node_t) - 1)) & ~(sizeof(node_t) - 1))

#define PRINTF_GREEN(...)         \
    fprintf(stderr, "\033[32m");  \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\033[0m");

static void *arena_start = NULL;
static size_t arena_size = 0;
size_t remaining = 0;

int statusno = 0;

int myinit(size_t size)
{
    if (size <= 0 || size > MAX_ARENA_SIZE)
    {
        statusno = ERR_BAD_ARGUMENTS;
        return statusno; // Return an error code.
    }

    size_t page_size = getpagesize();

    PRINTF_GREEN("Initializing arena:\n");
    PRINTF_GREEN("...requested size %zu bytes\n", size);
    PRINTF_GREEN("...pagesize is %zu bytes\n", page_size);

    // size_t aligned_size = (size + page_size - 1) & ~(page_size - 1);
    size_t aligned_size = (size + page_size - 1) / page_size * page_size;

    PRINTF_GREEN("...adjusting size with page boundaries\n");
    PRINTF_GREEN("...adjusted size is %zu bytes\n", aligned_size);

    arena_start = mmap(NULL, aligned_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (arena_start == MAP_FAILED)
    {
        statusno = ERR_SYSCALL_FAILED;
        return -1; // Failed to initialize the arena.
    }

    arena_size = aligned_size;
    remaining = aligned_size;

    PRINTF_GREEN("...mapping arena with mmap()\n");
    PRINTF_GREEN("...arena starts at %p\n", arena_start);
    PRINTF_GREEN("...arena ends at %p\n", (char *)arena_start + arena_size);
    node_t *initial_header = (node_t *)arena_start;
    initial_header->size = aligned_size - sizeof(node_t);
    initial_header->is_free = 1;
    initial_header->fwd = NULL;
    initial_header->bwd = NULL;

    statusno = 0; // Set statusno to indicate success.

    return arena_size; // Return arena size.
}

int mydestroy()
{
    if (arena_size == 0)
    {
        statusno = ERR_UNINITIALIZED;
        return statusno; // Arena was not initialized.
    }
    PRINTF_GREEN("Destroying Arena:\n");
    PRINTF_GREEN("...unmapping arena with munmap()\n");

    if (munmap(arena_start, arena_size) == -1)
    {
        statusno = ERR_SYSCALL_FAILED;
        return statusno; // Failed to destroy the arena.
    }

    arena_start = NULL;
    arena_size = 0;
    statusno = 0; // Set statusno to indicate success.

    return 0; // Return success.
}

void *myalloc(size_t size)
{
    if (arena_size == 0)
    {
        statusno = ERR_UNINITIALIZED;
        return NULL;
    }

    size_t aligned_size = ALIGN(size); // Include space for node_t structure

    // Check if the requested size with the header exceeds the available memory
    if (aligned_size + sizeof(node_t) > remaining)
    {
        statusno = ERR_OUT_OF_MEMORY;
        return NULL;
    }

    node_t *header = (node_t *)arena_start;

    while (header->fwd != NULL)
    {
        if (header->is_free && header->size >= aligned_size)
        {
            break;
        }
        header = header->fwd;
    }

    if (header == NULL)
    {
        statusno = ERR_OUT_OF_MEMORY;
        return NULL;
    }

    if (header->size - aligned_size >= sizeof(node_t))
    {
        node_t *new_header = (node_t *)((char *)header + aligned_size) + sizeof(node_t);
        new_header->size = header->size - aligned_size - sizeof(node_t);
        new_header->is_free = 1;
        new_header->fwd = header->fwd;
        new_header->bwd = header;

        header->size = aligned_size;
        header->fwd = new_header;
    }

    header->is_free = 0;

    remaining -= aligned_size + sizeof(node_t);

    return (void *)((char *)header + sizeof(node_t));
}

void myfree(void *ptr)
{
    if (ptr == NULL)
    {
        printf("Trying to free a NULL pointer.\n");
        return;
    }

    node_t *header = (node_t *)((char *)ptr - sizeof(node_t));

    if (header->is_free)
    {
        printf("Error: Trying to free an already freed block.\n");
        return;
    }

    header->is_free = 1;

    // Coalesce with the next chunk if it's free
    while (header->fwd != NULL && header->fwd->is_free)
    {
        header->size += header->fwd->size + sizeof(node_t);
        header->fwd = header->fwd->fwd;
        if (header->fwd != NULL)
        {
            header->fwd->bwd = header;
        }
    }

    // Coalesce with the previous chunk if it's free
    while (header->bwd != NULL && header->bwd->is_free)
    {
        header->bwd->size += header->size + sizeof(node_t);
        header->bwd->fwd = header->fwd;
        if (header->fwd != NULL)
        {
            header->fwd->bwd = header->bwd;
        }
        header = header->bwd;
    }
}
