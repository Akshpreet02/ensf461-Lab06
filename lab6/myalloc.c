#include <stddef.h>
#include "myalloc.h"

//NO USING MALLOC() IN THIS FILE

//FUNCTION: myinit
//INPUT: size_t size
//OUTPUT: returns 1 if successful, 0 if not
//DESCRIPTION: initializes the memory allocator using mmap() to allocate a
//large area of memory. The size of the area is specified by the size argument.
//The size argument must be a multiple of the page size. If the size argument
//is not a multiple of the page size, then the function returns 0. If the size
//argument is larger than the maximum size that can be allocated, then the
//function returns 0. If the size argument is 0, then the function returns 0.
//If the function is successful, then it returns 1. If the function fails, then
//it returns 0.
int myinit(size_t size){ // initialize the memory allocator

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
void* myalloc(size_t size){}


//FUNCTION: myfree
//INPUT: void* ptr
//OUTPUT: none
//DESCRIPTION: frees a block of memory that was previously allocated using
//myalloc(). If the ptr argument is NULL, then the function does nothing. If
//the ptr argument is not NULL, but it was not returned by a previous call to
//myalloc(), then the function does nothing. If the ptr argument is not NULL
//and it was returned by a previous call to myalloc(), then the function frees
//the block of memory and makes it available for future allocations.
void myfree(void* ptr){} 


//FUNCTION: mydestroy
//INPUT: none
//OUTPUT: returns 1 if successful, 0 if not
//DESCRIPTION: destroys the memory allocator. Any existing allocated memory
//blocks are freed. After this function is called, any future calls to myalloc()
//or myfree() will fail. If the function is successful, then it returns 1. If
//the function fails, then it returns 0.
int mydestroy(){}
