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

#ifndef THREADED
#error Direct interpreter cannot be built non-threaded
#endif

/* Macros for handler/bytecode rewriting */

#ifdef USE_CACHE
#define WITH_OPCODE_CHANGE_CP_DINDEX(opcode, index, cache) \
{                                                          \
    index = pc->operand.uui.u1;                            \
    cache = pc->operand.uui.i;                             \
    if(pc->handler != L(opcode, 0, ENTRY) &&               \
       pc->handler != L(opcode, 1, ENTRY) &&               \
       pc->handler != L(opcode, 2, ENTRY))                 \
        goto *pc->handler;                                 \
}

#else /* USE_CACHE */

#define WITH_OPCODE_CHANGE_CP_DINDEX(opcode, index, cache) \
{                                                          \
    index = pc->operand.uui.u1;                            \
    cache = pc->operand.uui.i;                             \
    if(pc->handler != L(opcode, 0, ENTRY))                 \
        goto *pc->handler;                                 \
}
#endif

#define OPCODE_REWRITE(opcode, cache, new_operand)         \
{                                                          \
    pc->handler = &&rewrite_lock;                          \
    MBARRIER();                                            \
    pc->operand = new_operand;                             \
    MBARRIER();                                            \
    pc->handler = handlers[cache][opcode];                 \
                                                           \
    checkInliningQuickenedInstruction(pc, mb);             \
}

/* Two levels of macros are needed to correctly produce the label
 * from the OPC_xxx macro passed into DEF_OPC as cpp doesn't 
 * prescan when concatenating with ##...
 *
 * On gcc <= 2.95, we also get a space inserted before the :
 * e.g DEF_OPC(OPC_NULL) -> opc0 : - the ##: is a hack to fix
 * this, but this generates warnings on >= 2.96...
 */
#if (__GNUC__ == 2) && (__GNUC_MINOR__ <= 95)
#define label(x, y, z)                          \
opc##x##_##y##_##z##:
#else
#define label(x, y, z)                          \
opc##x##_##y##_##z:
#endif

#define DEF_OPC(opcode, level, BODY)            \
    label(opcode, level, START)                 \
        PAD                                     \
    label(opcode, level, ENTRY)                 \
        BODY                                    \
    label(opcode, level, END)                   \
        goto *pc->handler;

#define DEF_OPC_2(op1, op2, level, BODY)        \
    DEF_OPC(op1, level, BODY);                  \
    DEF_OPC(op2, level, BODY);

#define DEF_OPC_3(op1, op2, op3, level, BODY)   \
    DEF_OPC(op1, level, BODY);                  \
    DEF_OPC(op2, level, BODY);                  \
    DEF_OPC(op3, level, BODY);

#define DEF_OPC_012_2(op1, op2, BODY)           \
    DEF_OPC_012(op1, BODY)                      \
    DEF_OPC_012(op2, BODY)

#define DEF_OPC_012_3(op1, op2, op3, BODY)      \
    DEF_OPC_012(op1, BODY)                      \
    DEF_OPC_012(op2, BODY)                      \
    DEF_OPC_012(op3, BODY)

#define DEF_OPC_012_4(op1, op2, op3, op4, BODY) \
    DEF_OPC_012(op1, BODY)                      \
    DEF_OPC_012(op2, BODY)                      \
    DEF_OPC_012(op3, BODY)                      \
    DEF_OPC_012(op4, BODY)

#define DEF_OPC_210_2(op1, op2, BODY)           \
    DEF_OPC_210(op1, BODY)                      \
    DEF_OPC_210(op2, BODY)

#define RW_LABELS(opcode)                       \
    RW_LABEL(opcode, START)                     \
    RW_LABEL(opcode, ENTRY)                     \
    RW_LABEL(opcode, END) 

#define DEF_OPC_RW(opcode, BODY)                \
    RW_LABELS(opcode)                           \
        BODY                                    \
        goto *pc->handler;

#define DEF_OPC_RW_4(op1, op2, op3, op4, BODY)  \
    RW_LABELS(op1)                              \
    RW_LABELS(op2)                              \
    RW_LABELS(op3)                              \
    RW_LABELS(op4)                              \
        BODY                                    \
        goto *pc->handler;

#ifdef USE_CACHE
#define DEF_OPC_012(opcode, BODY)               \
    DEF_OPC(opcode, 0, ({                       \
        cache.i.v2 = *--ostack;                 \
        cache.i.v1 = *--ostack;                 \
        __asm__("");                            \
        BODY                                    \
    });)                                        \
                                                \
    DEF_OPC(opcode, 1, ({                       \
        cache.i.v2 = cache.i.v1;                \
        cache.i.v1 = *--ostack;                 \
        __asm__("");                            \
        BODY                                    \
    });)                                        \
                                                \
    DEF_OPC(opcode, 2, ({BODY});)
        
#define DEF_OPC_210(opcode, BODY)               \
    DEF_OPC(opcode, 2, ({                       \
        *ostack++ = cache.i.v1;                 \
        *ostack++ = cache.i.v2;                 \
        __asm__("");                            \
        BODY                                    \
    });)                                        \
                                                \
    DEF_OPC(opcode, 1, ({                       \
        *ostack++ = cache.i.v1;                 \
        __asm__("");                            \
        BODY                                    \
    });)                                        \
                                                \
    DEF_OPC(opcode, 0, ({BODY});)
        
#define RW_LABEL(opcode, lbl)                   \
    label(opcode, 0, lbl)                       \
    label(opcode, 1, lbl)                       \
    label(opcode, 2, lbl)

#else /* USE_CACHE */

#define DEF_OPC_012(opcode, BODY)               \
    DEF_OPC(opcode, 0, BODY)

#define DEF_OPC_210(opcode, BODY)               \
    DEF_OPC(opcode, 0, BODY)

#define RW_LABEL(opcode, lbl)                   \
    label(opcode, 0, lbl)

#endif /* USE_CACHE */

#define DISPATCH_FIRST                          \
    goto *pc->handler;

#define DISPATCH_SWITCH

#define REDISPATCH ;

#define DISPATCH_RET(ins_len)                   \
    pc++;

#define DISPATCH_METHOD_RET(ins_len)            \
    goto *(++pc)->handler;

#define DISPATCH(level, ins_len)                \
    pc++;

#define BRANCH(TEST)                            \
    if(TEST)                                    \
        pc = (Instruction*) pc->operand.pntr;   \
    else                                        \
        pc++;

#define PREPARE_MB(mb)                          \
    if((uintptr_t)mb->code & 0x3)               \
        prepare(mb, handlers)

#define ARRAY_TYPE(pc)        pc->operand.i
#define SINGLE_INDEX(pc)      pc->operand.i
#define DOUBLE_INDEX(pc)      pc->operand.i
#define SINGLE_SIGNED(pc)     pc->operand.i
#define DOUBLE_SIGNED(pc)     pc->operand.i
#define IINC_LVAR_IDX(pc)     pc->operand.ii.i1
#define IINC_DELTA(pc)        pc->operand.ii.i2
#define INV_QUICK_ARGS(pc)    pc->operand.uu.u1
#define INV_QUICK_IDX(pc)     pc->operand.uu.u2
#define INV_INTF_IDX(pc)      pc->operand.uu.u1
#define INV_INTF_CACHE(pc)    pc->operand.uu.u2
#define MULTI_ARRAY_DIM(pc)   pc->operand.uui.u2
#define RESOLVED_CONSTANT(pc) pc->operand.u
#define RESOLVED_FIELD(pc)    ((FieldBlock*)pc->operand.pntr)
#define RESOLVED_METHOD(pc)   ((MethodBlock*)pc->operand.pntr)
#define RESOLVED_CLASS(pc)    (Class *)CP_INFO(cp, pc->operand.uui.u1)

/* Macros for checking for common exceptions */

#define THROW_EXCEPTION(excep_enum, message)   \
{                                              \
    frame->last_pc = pc;                       \
    signalException(excep_enum, message);      \
    goto throwException;                       \
}

#define NULL_POINTER_CHECK(ref)                \
    if(!ref) {                                 \
        __asm__("");                           \
        goto *throwNullLabel;                  \
    }

#define ZERO_DIVISOR_CHECK(value)              \
    if(value == 0) {                           \
        __asm__("");                           \
        goto *throwArithmeticExcepLabel;       \
    }

#define ARRAY_BOUNDS_CHECK(array, idx)         \
    if(idx >= ARRAY_LEN(array)) {              \
        __asm__("");                           \
        oob_array_index = idx;                 \
        goto *throwOOBLabel;                   \
    }

#define MAX_INT_DIGITS 11

#ifndef PAD
#define PAD __asm__("");
#endif

extern void initialiseDirect(InitArgs *args);
extern void inlineBlockWrappedOpcode(MethodBlock *mb, Instruction *pc);
extern void prepare(MethodBlock *mb, const void ***handlers);
extern void checkInliningQuickenedInstruction(Instruction *pc, MethodBlock *mb);

