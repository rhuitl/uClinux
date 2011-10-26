/*
 * Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008
 * Robert Lougher <rob@lougher.org.uk>.
 *
 * This file is part of JamVM.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/* Must be included first to get configure options */
#include "jam.h"

#ifdef INLINING
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "hash.h"
#include "inlining.h"

/* To do inlining, we must know which handlers are relocatable.  This
   can be calculated either at runtime or at compile-time as part of
   the build.  Doing it at compile-time saves having a second copy of
   the interpreter and the runtime checks, reducing executable size by
   approx 20-30%.  However, it cannot be done at compile-time when
   cross-compiling (at least without extra effort).
*/
#ifdef RUNTIME_RELOC_CHECKS
static int handler_sizes[HANDLERS][LABELS_SIZE];
static int goto_len;
#else
#include "relocatability.inc"
#endif

#ifdef TRACEINLINING
#define TRACE(fmt, ...) jam_printf(fmt, ## __VA_ARGS__)
#else
#define TRACE(fmt, ...)
#endif

#define HASHTABSZE 1<<10
#define HASH(ptr) codeBlockHash(ptr)
#define COMPARE(ptr1, ptr2, hash1, hash2) ((ptr2 != DELETED) && \
                                           (hash1 == hash2) && codeBlockComp(ptr1, ptr2))
#define PREPARE(ptr) allocCodeBlock(ptr)
#define FOUND(ptr) foundExistingBlock(ptr)
#define SCAVENGE(ptr) ptr == DELETED
#define DELETED ((void*)-1)

/* Global lock protecting handler rewriting */
static VMLock rewrite_lock;

#define CODE_INCREMENT 128*KB
#define ALIGN(size) ROUND(size, sizeof(CodeBlockHeader))
#define ROUND(size, round) (size + round - 1) / round * round

typedef struct code_block_header {
    int len;
    union {
        int ref_count;
        struct code_block_header *next;
    } u;
} CodeBlockHeader;

static HashTable code_hash_table;

static int replication_threshold;

static int code_size = 0;
static int sys_page_size;
static int code_increment;
static unsigned int max_code_size;
static CodeBlockHeader *code_free_list = NULL;

static char *min_entry_point = (char*)-1;
static char *max_entry_point  = NULL;

static int enabled;
int inlining_inited = FALSE;
static char **handler_entry_points[HANDLERS];
static char *goto_start;

char *reason(int reason) {
    switch(reason) {
        case MEMCMP_FAILED:
            return "memory compare failed";

        case END_REORDERED:
            return "end label re-ordered";

        case END_BEFORE_ENTRY:
            return "end label before entry label";
    }
    return "unknown reason";
}

void showRelocatability() {
    int i;

#ifdef RUNTIME_RELOC_CHECKS
    goto_len = calculateRelocatability(handler_sizes);
#endif

    if(goto_len >= 0)
        printf("Dispatch sequence is relocatable\n");
    else
        printf("Dispatch sequence is not relocatable (%s)\n", reason(goto_len));

    for(i = 0; i < HANDLERS; i++) {
        int j;

        printf("Opcodes at depth %d: \n", i);

        for(j = 0; j < LABELS_SIZE; j++) {
            int size = handler_sizes[i][j];

            if(size >= 0)
                printf("%d : is relocatable\n", j);
            else
                printf("%d : is not relocatable (%s)\n", j, reason(size));
        }
    }
}

int checkRelocatability() {
    char ***handlers = (char ***)executeJava();
    int i;

#ifdef RUNTIME_RELOC_CHECKS
    goto_len = calculateRelocatability(handler_sizes);
#endif

    /* Check relocatability of the indirect goto.  This is copied onto the end
       of each super-instruction.  If this is un-relocatable,  inlining is
       disabled. */

    if(goto_len < 0)
        return FALSE;

    goto_start = handlers[ENTRY_LABELS][GOTO_START];

    /* Calculate handler code range within the program text.
       This is used to tell which handlers in a method have
       been rewritten when freeing the method data on class
       unloading */

    for(i = 0; i < HANDLERS; i++) {
        int j;

        for(j = 0; j < LABELS_SIZE; j++) {
            char *entry = handlers[ENTRY_LABELS+i][j];

            if(entry < min_entry_point)
                min_entry_point = entry;

            if(entry > max_entry_point)
                max_entry_point = entry;
        }

        handler_entry_points[i] = handlers[ENTRY_LABELS+i];
    }

    return TRUE;
}

int initialiseInlining(InitArgs *args) {
    enabled = args->codemem > 0 ? checkRelocatability() : FALSE;

    if(enabled) {
        initVMLock(rewrite_lock);
        initHashTable(code_hash_table, HASHTABSZE, TRUE);

        sys_page_size = getpagesize();
        max_code_size = ROUND(args->codemem, sys_page_size);
        code_increment = ROUND(CODE_INCREMENT, sys_page_size);

        replication_threshold = args->replication;
    }

    inlining_inited = TRUE;
    return enabled;
}

int codeBlockHash(CodeBlockHeader *block) {
    int hash = 0;
    int len = block->len - sizeof(CodeBlockHeader);
    unsigned char *pntr = (unsigned char *)(block + 1);

    for(; len > 0; len--)
        hash = hash * 37 + *pntr++;

    return hash;
}

int codeBlockComp(CodeBlockHeader *block, CodeBlockHeader *hashed_block) {
    if(block->len != block->len)
        return FALSE;

    return memcmp(block + 1, hashed_block + 1, block->len - sizeof(CodeBlockHeader)) == 0;
}

int compareLabels(const void *pntr1, const void *pntr2) {
    char *v1 = *(char **)pntr1;
    char *v2 = *(char **)pntr2;

    return v1 - v2;
}

void addToFreeList(CodeBlockHeader **blocks, int len) {
    CodeBlockHeader *last = NULL;
    CodeBlockHeader **block_pntr = blocks;
    CodeBlockHeader *free_pntr = code_free_list;

    qsort(blocks, len, sizeof(CodeBlockHeader*), compareLabels);

    for(; len--; block_pntr++) {
        for(; free_pntr && free_pntr < *block_pntr; last = free_pntr, free_pntr = free_pntr->u.next);

        if(last) {
            if((char*)last + last->len == (char*)*block_pntr) {
                last->len += (*block_pntr)->len;
                goto out;
            }
            last->u.next = *block_pntr;
        } else
            code_free_list = *block_pntr;

        (*block_pntr)->u.next = free_pntr;
        last = *block_pntr;

out:
        if((char*)last + last->len == (char*)free_pntr) {
            last->u.next = free_pntr->u.next;
            last->len += free_pntr->len;
            free_pntr = last;
        }
    }
}

void freeMethodInlinedInfo(MethodBlock *mb) {
    Instruction *instruction = mb->code;
    CodeBlockHeader **blocks = mb->code;
    QuickPrepareInfo *info;
    int i;

    if(!enabled)
        return;

    /* Scan handlers within the method */

    for(i = mb->code_size; i--; instruction++) {
        char *handler = (char*)instruction->handler;
        CodeBlockHeader *block;

        if(handler >= min_entry_point || handler <= max_entry_point) {
            /* Handler is within the program text and so does
               not need freeing.  However, sequences which
               have not been rewritten yet will have associated
               preparation info. */
            if(handler == handler_entry_points[0][OPC_INLINE_REWRITER])
                gcPendingFree(instruction->operand.pntr);

            continue;
        }

        /* The handler is an inlined block */
        block = ((CodeBlockHeader*)handler) - 1;

        if(block->u.ref_count <= 0) {
            /* Either a duplicate block, or a hashed block and this
               is the only reference to it.  Duplicates must be freed
               as this would be a leak.  Hashed blocks potentially
               will be re-used and so we could keep them around.
               However, we free them because it's better to free
               room for a potentially more useful sequence. */

            /* Add onto list to be freed */
            *blocks++ = block;

            if(block->u.ref_count == 0)
                deleteHashEntry(code_hash_table, block, FALSE);
        } else
            block->u.ref_count--;
    }

    if(blocks > (CodeBlockHeader**)mb->code)
        addToFreeList(mb->code, blocks - (CodeBlockHeader**)mb->code);

    for(info = mb->quick_prepare_info; info != NULL;) {
        QuickPrepareInfo *temp = info;
        info = info->next;
        gcPendingFree(temp);
    }
}

CodeBlockHeader *expandCodeMemory(int size) {
    CodeBlockHeader *block;
    int inc = size < code_increment ? code_increment
                                    : ROUND(size, sys_page_size);

    if(code_size + inc > max_code_size) {
        inc = max_code_size - code_size;
        if(inc < size)
            return NULL;
    }

    block = mmap(0, inc, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANON, -1, 0);

    if(block == MAP_FAILED)
        return NULL;

    block->len = size;
    if(inc != size) {
        CodeBlockHeader *rem = (CodeBlockHeader*)((char*)block + size);

        rem->len = inc - size;
        addToFreeList(&rem, 1);
    }

    code_size += inc;
    return block;
}

CodeBlockHeader *allocCodeMemory(int size) {
    CodeBlockHeader *last = NULL;
    CodeBlockHeader *block = code_free_list;

    /* Search free list for big enough block */
    for(; block && block->len < size; last = block, block = block->u.next);

    if(block) {
        /* Found one.  If not exact fit, need to split. */
        if(block->len > size) {
            CodeBlockHeader *rem = (CodeBlockHeader*)((char*)block + size);

            rem->len = block->len - size;
            rem->u.next = block->u.next;

            block->len = size;
            block->u.next = rem;
        }

        if(last)
            last->u.next = block->u.next;
        else
            code_free_list = block->u.next;
    } else {
        /* No block big enough.  Need to allocate a new code chunk */
        block = expandCodeMemory(size);
    }

    return block;
}
    
CodeBlockHeader *copyCodeBlock(CodeBlockHeader *dest_block, CodeBlockHeader *src_block) {
    int len = src_block->len - sizeof(CodeBlockHeader);

    memcpy(dest_block + 1, src_block + 1, len);
    FLUSH_CACHE(dest_block + 1, len);

    return dest_block;
}

CodeBlockHeader *foundExistingBlock(CodeBlockHeader *block) {
    /* If the number of usages of the block has reached the replication
       threshold duplicate the block */
    if(block->u.ref_count >= replication_threshold) {
        CodeBlockHeader *new_block = allocCodeMemory(block->len);

        if(new_block != NULL) {
            /* Flag block as being a duplicate */
            new_block->u.ref_count = -1;
            return copyCodeBlock(new_block, block);
        }
    }

    /* Either no code memory for duplicate or not reached
       replication threshold. Just increase usage count */
    block->u.ref_count++;

    return block;
}

/* Executed when the code block does not already exist in the
   hash table */
CodeBlockHeader *allocCodeBlock(CodeBlockHeader *block) {
    CodeBlockHeader *new_block = allocCodeMemory(block->len);

    if(new_block != NULL) {
        new_block->u.ref_count = 0;
        copyCodeBlock(new_block, block);
    }

    return new_block;
}

CodeBlockHeader *findCodeBlock(CodeBlockHeader *block) {
    CodeBlockHeader *hashed_block;

    /* Search hash table.  Add if absent, scavenge and locked */
    findHashEntry(code_hash_table, block, hashed_block, TRUE, TRUE, TRUE);

    return hashed_block;
}

void inlineSequence(MethodBlock *mb, CodeBlock *info, int start, int len) {
    int code_len = goto_len + sizeof(CodeBlockHeader);
    Instruction *instructions = &info->start[start];
    OpcodeInfo *opcodes = &info->opcodes[start];
    CodeBlockHeader *hashed_block, *block;
    int aligned_len, i;
    char *pntr;

    /* Calculate sequence length */
    for(i = 0; i < len; i++)
        code_len += handler_sizes[opcodes[i].cache_depth][opcodes[i].opcode];

    aligned_len = ALIGN(code_len);

    /* We malloc memory for the block rather than allocating code memory.
       This reduces fragmentation of the code memory in the case where we
       use an existing block and must free the new sequence */
    block = sysMalloc(aligned_len);

    /* Store length at beginning of sequence */
    block->len = aligned_len;
    pntr = (char *)(block + 1);

    /* Concatenate the handler bodies together */
    for(i = 0; i < len; i++) {
        int size = handler_sizes[opcodes[i].cache_depth][opcodes[i].opcode];

        memcpy(pntr, instructions[i].handler, size);
        pntr += size;
    }

    /* Add the dispatch onto the end of the super-instruction */
    memcpy(pntr, goto_start, goto_len);

    /* Pad with zeros up to block length */
    for(pntr += goto_len; code_len < aligned_len; code_len++)
        *pntr++ = 0;

    /* Look up new block in inlined block cache */
    hashed_block = findCodeBlock(block);
    sysFree(block);

    if(hashed_block != NULL) {
        /* Replace first handler with new inlined block */
        instructions[0].handler = hashed_block + 1;
        MBARRIER();

        TRACE("InlineSequence %s start %p (%d) instruction len %d code len %d sequence %p\n",
              mb->name, instructions, start, len, code_len, instructions[0].handler);
    }
}

void inlineBlock(MethodBlock *mb, CodeBlock *block) {
    int start, len, i;

    for(start = i = 0; i < block->length; i++) {
        int cache_depth = block->opcodes[i].cache_depth;
        int opcode = block->opcodes[i].opcode;
        int op1, op2;

        /* The block opcodes contain the "un-quickened" opcode.
           This could have been quickened to one of several quick
           versions. */
        switch(opcode) {
            case OPC_LDC:
                op1 = OPC_LDC_QUICK;
                op2 = OPC_LDC_W_QUICK;
                break;

            case OPC_GETSTATIC:
                op1 = OPC_GETSTATIC_QUICK;
                op2 = OPC_GETSTATIC2_QUICK;
                break;

             case OPC_PUTSTATIC:
                op1 = OPC_PUTSTATIC_QUICK;
                op2 = OPC_PUTSTATIC2_QUICK;
                break;

            case OPC_GETFIELD:
                op1 = OPC_GETFIELD_QUICK;
                op2 = OPC_GETFIELD2_QUICK;
                break;

            case OPC_PUTFIELD:
                op1 = OPC_PUTFIELD_QUICK;
                op2 = OPC_PUTFIELD2_QUICK;
                break;

            case OPC_NEW: case OPC_ANEWARRAY: case OPC_CHECKCAST:
            case OPC_INVOKESTATIC: case OPC_INVOKEINTERFACE:
            case OPC_INVOKEVIRTUAL: case OPC_INVOKESPECIAL:
            case OPC_MULTIANEWARRAY: case OPC_INSTANCEOF:
                op1 = op2 = GOTO_END;
                break;

            default:
                op1 = op2 = -1;
                break;
        }

        if(op1 > 0) {
            /* Match which quickened opcode */
            opcode = handler_entry_points[cache_depth][op1]
                            == (char*) block->start[i].handler ? op1 : op2;
            block->opcodes[i].opcode = opcode;
        }

        /* A non-relocatable opcode ends a sequence */
        if(handler_sizes[cache_depth][opcode] < 0) {
            len = i - start;

            if(len > 0)
                inlineSequence(mb, block, start, len);

            start = i + 1;
        }
    }

    /* Inline the remaining sequence */
    len = block->length - start;
    if(len > 0)
        inlineSequence(mb, block, start, len);

    sysFree(block->opcodes);
}

void rewriteLock(Thread *self) {
    /* Only disable/enable suspension (slow) if
       we have to block */
    if(!tryLockVMLock(rewrite_lock, self)) {
        disableSuspend(self);
        lockVMLock(rewrite_lock, self);
        enableSuspend(self);
    }
}

void rewriteUnlock(Thread *self) {
    unlockVMLock(rewrite_lock, self);
}

void inlineBlockWrappedOpcode(MethodBlock *mb, Instruction *pc) {
    PrepareInfo *prepare_info = pc->operand.pntr;
    OpcodeInfo *info;
    int i;

    Thread *self = threadSelf();
    rewriteLock(self);

    for(i = 0; i < HANDLERS; i++)
        if(pc->handler == handler_entry_points[i][OPC_INLINE_REWRITER])
            break;

    if(i == HANDLERS) {
        rewriteUnlock(self);
        return;
    }

    pc->handler = handler_entry_points[0][GOTO_START];
    rewriteUnlock(self);

    /* Unwrap the original handler's operand */
    pc->operand = prepare_info->operand;
    MBARRIER();

    /* Unwrap the original handler */
    info = &prepare_info->block.opcodes[prepare_info->block.length-1];
    pc->handler = handler_entry_points[info->cache_depth][info->opcode];

    inlineBlock(mb, &prepare_info->block);
    sysFree(prepare_info);
}

/* A method's quick prepare info list holds prepare information for all
   blocks within the method that end with a quickened instruction.  If
   the quickened instruction being executed is in the list we must have
   reached the end of a block and we need to inline it */
void checkInliningQuickenedInstruction(Instruction *pc, MethodBlock *mb) {

    /* As there could be multiple threads executing this method,
       the list must be protected with a lock.  However, the 
       fast case of an empty list doesn't need locking. */
    if(mb->quick_prepare_info) {
        QuickPrepareInfo *info, *last = NULL;

        Thread *self = threadSelf();
        rewriteLock(self);

        /* Search list */
        info = mb->quick_prepare_info;
        for(; info && info->quickened != pc; last = info, info = info->next);

        /* If prepare info found, remove it from the list */
        if(info) {
            if(last)
                last->next = info->next;
            else
                mb->quick_prepare_info = info->next;
        }

        rewriteUnlock(self);

        /* If prepare info found, inline block (no need to
           hold lock) */
        if(info) {
            inlineBlock(mb, &info->block);
            sysFree(info);
        }
    }
}
#endif
