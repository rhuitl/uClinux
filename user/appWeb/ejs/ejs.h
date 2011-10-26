///
///	@file 	ejs.h
/// @brief 	Embedded Javascript (ECMAScript)
///
///	The Embedded Javascript header defines the Embedded Javascript API and 
///	internal structures.
/// 
////////////////////////////////////////////////////////////////////////////////
//
//	Copyright (c) Mbedthis Software LLC, 2003-2004. All Rights Reserved.
//	Portions Copyright (c) GoAhead Software, 1995-2000. All Rights Reserved.
//	The latest version of this code is available at http://www.mbedthis.com
//
//	This software is open source; you can redistribute it and/or modify it 
//	under the terms of the GNU General Public License as published by the 
//	Free Software Foundation; either version 2 of the License, or (at your 
//	option) any later version.
//
//	This program is distributed WITHOUT ANY WARRANTY; without even the 
//	implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
//	See the GNU General Public License for more details at:
//	http://www.mbedthis.com/downloads/gplLicense.html
//	
//	This General Public License does NOT permit incorporating this software 
//	into proprietary programs. If you are unable to comply with the GPL, a 
//	commercial license for this software and support services are available
//	from Mbedthis Software at http://www.mbedthis.com
//
////////////////////////////////// Includes ////////////////////////////////////
#ifndef _h_EJS
#define _h_EJS 1

#include	"mpr.h"

///////////////////////////// Forward Declarations /////////////////////////////

class 	MprEjs;
class 	MprEjsProc;
class 	MprEjsService;
class 	MprEjsFunction;
class 	MprEjsInput;
class 	MprEjsLex;
class 	MprEjsTrace;

////////////////////////////////// Constants ///////////////////////////////////

#define EJS_INC				128			// Growth for tags/tokens 
#define EJS_SCRIPT_INC		1024		// Growth for js scripts 
#define EJS_OFFSET			1			// hAlloc doesn't like 0 entries 
#define EJS_MAX_RECURSE		100			// Sanity for maximum recursion 
#define	EJS_OCTAL			8
#define	EJS_HEX				16
#define	EJS_DEFAULT_ARGC	16

//
//	Expression operators
// 
#define EJS_EXPR_LESS			1		// < 
#define EJS_EXPR_LESSEQ			2		// <= 
#define EJS_EXPR_GREATER		3		// > 
#define EJS_EXPR_GREATEREQ		4		// >= 
#define EJS_EXPR_EQ				5		// == 
#define EJS_EXPR_NOTEQ			6		// != 
#define EJS_EXPR_PLUS			7		// + 
#define EJS_EXPR_MINUS			8		// - 
#define EJS_EXPR_DIV			9		// / 
#define EJS_EXPR_MOD			10		// % 
#define EJS_EXPR_LSHIFT			11		// << 
#define EJS_EXPR_RSHIFT			12		// >> 
#define EJS_EXPR_MUL			13		// * 
#define EJS_EXPR_ASSIGNMENT		14		// = 
#define EJS_EXPR_INC			15		// ++ 
#define EJS_EXPR_DEC			16		// -- 
#define EJS_EXPR_BOOL_COMP		17		// ! 

//
//	Conditional operators
// 
#define EJS_COND_AND			1		// && 
#define EJS_COND_OR				2		// || 
#define EJS_COND_NOT			3		// ! 

//
//	Defines whether a unary minus is acceptable after the last token.
// 
#define	EJS_UNARY_MINUS_NOT_OK	0
#define	EJS_UNARY_MINUS_OK		1

//
//	States
// 
#define EJS_STATE_ERR			-1		// Error state 
#define EJS_STATE_EOF			1		// End of file 
#define EJS_STATE_COND			2		// Parsing a "(conditional)" stmt 
#define EJS_STATE_EJS_COND_DONE	3
#define EJS_STATE_RELEXP		4		// Parsing a relational expr 
#define EJS_STATE_RELEXP_DONE	5
#define EJS_STATE_EXPR			6		// Parsing an expression 
#define EJS_STATE_EJS_EXPR_DONE	7
#define EJS_STATE_STMT			8		// Parsing General statement 
#define EJS_STATE_STMT_DONE		9
#define EJS_STATE_STMT_BLOCK_DONE 10	// End of block "}" 
#define EJS_STATE_ARG_LIST		11		// Function arg list 
#define EJS_STATE_ARG_LIST_DONE	12
#define EJS_STATE_DEC_LIST		16		// Declaration list 
#define EJS_STATE_DEC_LIST_DONE	17
#define EJS_STATE_DEC			18
#define EJS_STATE_DEC_DONE		19
#define EJS_STATE_RET			20		// Return statement 

#define EJS_STATE_BEGIN			EJS_STATE_STMT

//
//	Flags. Used in Ejs and as parameter to parse()
//
#define EJS_FLAGS_EXE			0x1		// Execute statements 
#define EJS_FLAGS_VARIABLES		0x2		// Allocated variables store 
#define EJS_FLAGS_FUNCTIONS		0x4		// Allocated function store 

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// MprEjsProc ///////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MprEjsProc : public MprHashEntry {
  private:
	MprStr			name;
  protected:
	MprEjs			*scriptEngine;
  public:
					MprEjsProc(MprEjs *js, char *name);
					MprEjsProc(char *name);
	virtual			~MprEjsProc();
	MprScriptEngine	*getScriptEngine();
	void			setScriptEngine(MprEjs *js);
	virtual int		run(void *userHandle, int argc, char **argv) = 0;
};

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// MprEjsInput //////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MprEjsSaveInput {
  public:
	char			*tokbufStart;
	char			*scriptStart;
	char			*putBackToken;
	int				unaryMinusState;
	int				putBackTokenId;

					MprEjsSaveInput() {
						tokbufStart = 0;
						scriptStart = 0;
						putBackToken = 0;
						unaryMinusState = 0;
						putBackTokenId = 0;
					}
};

class MprEjsInput {
  protected:
	MprBuf			tokbuf;				// Current token 
	MprBuf			script;				// Input script for parsing 
	char			*putBackToken;		// Putback token string 
	int				putBackTokenId;		// Putback token ID 
	int				unaryMinusState;	// is unary minus OK now 
	char			*line;				// Current line 
	int				lineLength;			// Current line length 
	int				lineNumber;			// Parse line number 
	int				lineColumn;			// Column in line 

  public:
					MprEjsInput();
					~MprEjsInput();
	void			reset();
	void			freeInputState(MprEjsSaveInput *state);
	int				getChar();
	void			putback(int c);
	void			restoreInputState(MprEjsSaveInput *state);
	void			saveInputState(MprEjsSaveInput *state);
	void			setScript(char *script);
	int				charConvert(int base, int maxDig);

private:
	friend class	MprEjsLex;
	friend class	MprEjs;
};

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// MprEjsLex ///////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//	Lexical analyser tokens
// 
#define EJS_TOK_ERR				-1		// Any error 
#define EJS_TOK_LPAREN			1		// ( 
#define EJS_TOK_RPAREN			2		// ) 
#define EJS_TOK_IF				3		// if 
#define EJS_TOK_ELSE			4		// else 
#define EJS_TOK_LBRACE			5		// { 
#define EJS_TOK_RBRACE			6		// } 
#define EJS_TOK_LOGICAL			7		// ||, &&, ! 
#define EJS_TOK_EXPR			8		// +, -, /, % 
#define EJS_TOK_SEMI			9		// ; 
#define EJS_TOK_LITERAL			10		// literal string 
#define EJS_TOK_FUNCTION		11		// function name 
#define EJS_TOK_NEWLINE			12		// newline white space 
#define EJS_TOK_ID				13		// function name 
#define EJS_TOK_EOF				14		// End of script 
#define EJS_TOK_COMMA			15		// Comma 
#define EJS_TOK_VAR				16		// var 
#define EJS_TOK_ASSIGNMENT		17		// = 
#define EJS_TOK_FOR				18		// for 
#define EJS_TOK_INC_DEC			19		// ++, -- 
#define EJS_TOK_RETURN			20		// return 

class MprEjsLex {
  protected:
	MprEjs			*ejs;				// Just to reach error();
	MprEjsInput		*ip;				// Input evaluation block 
	char			*token;				// Pointer to token string 
	int				tokenId;			// Current token id 
  public:
					MprEjsLex(MprEjs *js);
					~MprEjsLex();
	void			closeScript();
	int				getLexicalToken(int state);
	int				getToken(int state);
	int				openScript(char *script);
	void			putbackToken(int tid, char *string);
	int				tokenAddChar(int c);

	friend class	MprEjs;
};

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// MprEjsService //////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MprEjsService : MprScriptService {
  public:
#if BLD_FEATURE_LOG
	MprLogModule	*logModule;
#endif

  protected:
	MprHashTable	*stndVars;
	MprHashTable	*stndProcs;

  public:
					MprEjsService();
					~MprEjsService();
	int				configure();
	void			insertProc(MprEjsProc *proc);
	void			setStndVar(char *var, char *value);
	MprScriptEngine	*newEngine(void *data, MprHashTable *vars, 
						MprHashTable *procs);

  private:
	void			setIntVar(char *var, char *value);

	friend class	MprEjs;
};

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// MprEjs /////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MprEjs : public MprScriptEngine {
  public:
	MprEjsService	*jsService;			// Pointer to JavaScript service object

  private:
	MprEjsLex		*lex;				// Lexical analyser object
	MprHashTable	*procs;				// Symbol table for procedures 
	MprHashTable	**vars;				// Array of variable tables 
	MprEjsFunction	*currentFunction;	// Current function being executed
	char			*result;			// Current expression result 
	char			*errorMsg;			// Error message 
	int				vid;				// ID of current local var space 
	int				vmax;				// Size of variable "stack" 
	int				flags;				// Flags 
	void			*userHandle;		// User defined handle 

  public:
					MprEjs(MprEjsService *service, MprHashTable *vars, 
						MprHashTable *procs);
					~MprEjs();
	void			error(char *fmt, ...);
	char			*evalScriptFile(char *path, char **emsg);
	char			*evalScriptBlock(char *script, char **emsg);
	char			*evalScript(char *script, char **emsg);
	MprHashTable	*getProcTable();
	int				getLineNumber();
	MprEjsProc*		getProc(char *name);
	char			*getResult();
	void			*getUserHandle();
	int				getVar(char *var, char **value);
	MprHashTable	*getVariableTable();
	void			insertProc(MprEjsProc *proc);
	void			removeProc(char *name);
	void			setEnvironmentVar(char *var, char *value);
	MprHashTable	*setProcTable(MprHashTable *procs);
	void			setGlobalVar(char *var, char *value);
	//	FUTURE - great to have a varargs version.
	void			setResult(char *s);
	void			setUserHandle(void *handle);
	void			setVar(char *var, char *value);

  private:
	void			appendString(char **ptr, char *s);
	int				closeBlock();
	int				evalCond(char *lhs, int rel, char *rhs);
	int				evalExpr(char *lhs, int rel, char *rhs);
	int				evalFunction();
	int				parse(int state, int flags);
	int				parseArgList(int state, int flags);
	int				parseCond(int state, int flags);
	int				parseDeclaration(int state, int flags);
	int				parseExpr(int state, int flags);
	int				parseStmt(int state, int flags);
	void			eatNewLines(int state);
	int				openBlock();

	// FUTURE -- OPT
	inline void		clearString(char **ptr) {
						if (*ptr) 
							mprFree(*ptr);
						*ptr = 0;
					};
	void			setString(char **ptr, char *s) {
						if (*ptr) 
							mprFree(*ptr);
						*ptr = mprStrdup(s);
					}
	friend class	MprEjsService;
};

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// MprEjsFunction ////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//	Function call class
//
 
class MprEjsFunction {
  public:
	char			*name;				// Function name 
	char			**argv;				// Arg list 
	int				argc;				// Count of args 
	int				argvSize;			// Physical size of malloced argv

  public:
					MprEjsFunction(char *name);
					~MprEjsFunction();
	void			insertArg(char *s);
};

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// MprEjsTrace ///////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MprEjsTraceProc : public MprEjsProc {
  public:
					MprEjsTraceProc(MprEjs *js, char *name) : 
						MprEjsProc(js, name) {};
					~MprEjsTraceProc() {};
	int				run(void *handle, int argc, char **argv);
};

///////////////////////////////// Prototypes ///////////////////////////////////
//
//	Routines for use in user defined JS procedures
//

extern int		mprParseArgs(int argc, char **argv, char *fmt, ...);

////////////////////////////////////////////////////////////////////////////////
#endif // _h_EJS

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
