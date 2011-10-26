
/********************************************
code.h
copyright 1991, Michael D. Brennan

This is a source file for mawk, an implementation of
the AWK programming language.

Mawk is distributed without warranty under the terms of
the GNU General Public License, version 2, 1991.
********************************************/


/* $Log: code.h,v $
 * Revision 1.5  1995/06/18  19:42:15  mike
 * Remove some redundant declarations and add some prototypes
 *
 * Revision 1.4  1994/12/13  00:13:01  mike
 * delete A statement to delete all of A at once
 *
 * Revision 1.3  1993/12/01  14:25:06  mike
 * reentrant array loops
 *
 * Revision 1.2  1993/07/22  00:04:01  mike
 * new op code _LJZ _LJNZ
 *
 * Revision 1.1.1.1  1993/07/03  18:58:10  mike
 * move source to cvs
 *
 * Revision 5.3  1993/01/14  13:11:11  mike
 * code2() -> xcode2()
 *
 * Revision 5.2  1993/01/07  02:50:33  mike
 * relative vs absolute code
 *
 * Revision 5.1  1991/12/05  07:59:07  brennan
 * 1.1 pre-release
 *
*/


/*  code.h  */

#ifndef  CODE_H
#define  CODE_H

#include "memory.h"

#define  PAGESZ	512
	/* number of code instructions allocated at one time */
#define  CODEWARN        16

/* coding scope */
#define   SCOPE_MAIN    0
#define   SCOPE_BEGIN   1  
#define   SCOPE_END     2
#define   SCOPE_FUNCT   3


typedef struct {
INST *base, *limit, *warn, *ptr ;
} CODEBLOCK ;

extern CODEBLOCK active_code ;
extern CODEBLOCK *main_code_p, *begin_code_p, *end_code_p ;

extern INST *main_start, *begin_start, *end_start  ;
extern unsigned main_size, begin_size  ;
extern INST *execution_start ;
extern INST *next_label ;  /* next statements jump to here */
extern int dump_code_flag ;

#define code_ptr  active_code.ptr
#define code_base active_code.base
#define code_warn active_code.warn
#define code_limit active_code.limit
#define code_offset (code_ptr-code_base)

#define INST_BYTES(x) (sizeof(INST)*(unsigned)(x))

extern  CELL  eval_stack[] ;
extern int exit_code ;


#define  code1(x)  code_ptr++ -> op = (x)
/* shutup picky compilers */
#define  code2(x,p)  xcode2(x,(PTR)(p))

void  PROTO(xcode2, (int, PTR)) ;
void  PROTO(code2op, (int, int)) ;
INST *PROTO(code_shrink, (CODEBLOCK*, unsigned*)) ;
void  PROTO(code_grow, (void)) ;
void  PROTO(set_code, (void)) ;
void  PROTO(be_setup, (int)) ;
void  PROTO(dump_code, (void)) ;


/*  the machine opcodes  */
/* to avoid confusion with a ptr FE_PUSHA must have op code 0 */
/* unfortunately enums are less portable than defines */

#define FE_PUSHA       0
#define FE_PUSHI       1
#define F_PUSHA        2
#define F_PUSHI        3
#define NF_PUSHI       4
#define _HALT          5
#define _STOP          6
#define _PUSHC         7
#define _PUSHD         8
#define _PUSHS         9
#define _PUSHINT       10
#define _PUSHA         11
#define _PUSHI         12
#define L_PUSHA        13
#define L_PUSHI        14
#define AE_PUSHA       15
#define AE_PUSHI       16
#define A_PUSHA        17
#define LAE_PUSHA      18
#define LAE_PUSHI      19
#define LA_PUSHA       20
#define _POP           21
#define _ADD           22
#define _SUB           23
#define _MUL           24
#define _DIV           25
#define _MOD           26
#define _POW           27
#define _NOT           28
#define _TEST          29
#define A_TEST         30
#define A_DEL          31
#define ALOOP          32
#define A_CAT          33
#define _UMINUS        34
#define _UPLUS         35
#define _ASSIGN        36
#define _ADD_ASG       37
#define _SUB_ASG       38
#define _MUL_ASG       39
#define _DIV_ASG       40
#define _MOD_ASG       41
#define _POW_ASG       42
#define F_ASSIGN       43
#define F_ADD_ASG      44
#define F_SUB_ASG      45
#define F_MUL_ASG      46
#define F_DIV_ASG      47
#define F_MOD_ASG      48
#define F_POW_ASG      49
#define _CAT           50
#define _BUILTIN       51
#define _PRINT         52
#define _POST_INC      53
#define _POST_DEC      54
#define _PRE_INC       55
#define _PRE_DEC       56
#define F_POST_INC     57
#define F_POST_DEC     58
#define F_PRE_INC      59
#define F_PRE_DEC      60
#define _JMP           61
#define _JNZ           62
#define _JZ            63
#define _LJZ           64
#define _LJNZ          65
#define _EQ            66
#define _NEQ           67
#define _LT            68
#define _LTE           69
#define _GT            70
#define _GTE           71
#define _MATCH0        72
#define _MATCH1        73
#define _MATCH2        74
#define _EXIT          75
#define _EXIT0         76
#define _NEXT          77
#define _RANGE         78
#define _CALL          79
#define _RET           80
#define _RET0          81
#define SET_ALOOP      82
#define POP_AL	       83
#define OL_GL          84
#define OL_GL_NR       85
#define _OMAIN         86
#define _JMAIN         87
#define DEL_A	       88	

#endif  /* CODE_H */
