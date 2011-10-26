#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Define the threshold above which we simply mmap the block of memory */
#define MMAP_THRESHOLD		200

/* Define the chunk of memory we alloc for our internal free list.  We choose something
 * that will definitely fit into a single page of memory.
 */
#define MMAP_BLOCK_SIZE		4080


/* We maintain our free storage list using a linked list of these */
struct free_list {
	size_t			 size;
	struct free_list	*next;
};

struct free_list *MY__malloc_free_list;


/* This routine attempts to grab a block of memory */
static void *MY_get_block(size_t len) {
	void *result;

	result = mmap((void *)0, len, PROT_READ | PROT_WRITE,
                 	MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (result == (size_t *) -1)
		return NULL;
	memset(result, 0, len);
	return result;
}


void *MY_malloc(size_t len)
{
	size_t		 *result;
	struct free_list *p;
	static void	 *current_block;
	static size_t	  current_space;

	/* Ensure the block will be large enough to fit onto our free list */
	if (len < sizeof(struct free_list) - sizeof(size_t))
		len = sizeof(struct free_list) - sizeof(size_t);

	/* Round to a four byte multiple for alignment purposes */
	len = (len + 3) & ~0x3;

	/* Check for a large block allocation.  We do these directly by
	 * calling mmap.  This means we don't have to track them and better
	 * still they get reclaimed by the system on free.  We don't account
	 * for any excess space that might be available at the end of the kernel
	 * allocation which could be kept in reserve for reallocs.
	 */
	if (len >= MMAP_THRESHOLD) {
		result = MY_get_block(len + sizeof(size_t));
		if (result == NULL)
			return NULL;

		*result++ = len;
		return result;
	}

	/* Search our free list for the best fitting block */
	if (MY__malloc_free_list != NULL) {
		struct free_list *q = NULL;
		struct free_list *bestp = NULL;
		struct free_list *bestq = 0;

		/* Search for the best fit in our free list */
		for (p = MY__malloc_free_list; p != NULL; p = (q = p)->next)
			if (p->size >= len) {
				if (bestp == NULL || p->size < bestp->size) {
					bestp = p;
					bestq = q;
					if (p->size == len)
						break;
				}
			}

		/* See if we found someting useable */
		if (bestp != NULL) {
			/* Unlink from free list */
			if (bestq != NULL)
				bestq->next = bestp->next;
			else
				MY__malloc_free_list = bestp->next;

			/* Convert into a allocated chunk */
			bestp->next = NULL;
			len = bestp->size;
			result = (size_t *)bestp;

			*result++ = len;
			return result;
		}
	}

	/* Nothing in free list, must check current block */
	if (current_space < len + sizeof(size_t)) {
		/* We've got to allocate a new block, throw what's left
		 * into the free list first.
		 */
		if (current_space >= sizeof(struct free_list)) {
			p = (struct free_list *)current_block;
			p->size = current_space - sizeof(size_t);
			p->next = MY__malloc_free_list;
			MY__malloc_free_list = p;
		}
		
		/* Grab a new hunk of memory */
		current_block = sbrk(len + sizeof(size_t));
		if (current_block == (void *)-1) {
			current_block = MY_get_block(MMAP_BLOCK_SIZE);
			if (current_block == NULL)
				return NULL;
			current_space = MMAP_BLOCK_SIZE;
		} else {
			current_space = len + sizeof(size_t);
		}
	}
	
	/* Allocate a chunk of memory now */
	result = current_block;
	current_block = ((char *) current_block) + len + sizeof(size_t);
	current_space -= len + sizeof(size_t);
	
	/* Check if there is insufficient memory left to allocate a free chunk and if
	 * there isn't add that space onto the current allocation unit so it doesn't get
	 * completly lost.
	 */
	if (current_space < sizeof(struct free_list)) {
		len += current_space;
		if (len >= MMAP_THRESHOLD)
			len = MMAP_THRESHOLD - 1;
		current_space = 0;
	}

	*result++ = len;
	return result;
}

void MY_free(void *ptr)
{
	if (ptr) {
		size_t *mem = ptr;
		size_t s;
		
		s = *--mem;	/* Grab size and real memory pointer */
	
		if (s >= MMAP_THRESHOLD)
			munmap(mem, s + sizeof(size_t));
		else {
			struct free_list *f = (struct free_list *)mem;
	
			f->size = s;
			f->next = MY__malloc_free_list;
			MY__malloc_free_list = f;
		}
	}
}
