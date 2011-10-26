///
///	@file 	ejs.cpp
/// @brief 	Javascript parser
///
///	JavaScript parser. This implementes a subset of the JavaScript language.
///	Multiple JavaScript parsers can be opened at a time.
/// 
///	@remarks This module is not thread-safe. It is the callers responsibility
///	to perform all thread synchronization.
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
/////////////////////////////////// Includes ///////////////////////////////////

#include	"ejs.h"

/////////////////////////////////// Defines ////////////////////////////////////
#if BLD_FEATURE_EJS_MODULE

#define	LOCAL_VAR_CHUNK_SIZE	16	// Variable stack grows this on realloc 

////////////////////////////////////// Code ////////////////////////////////////
//
//	Initialize a JavaScript engine
// 

MprEjs::MprEjs(MprEjsService *service, MprHashTable *varTable, 
	MprHashTable *procTable)
{
	jsService = service;
	errorMsg = 0;
	result = 0;
	userHandle = 0;
	currentFunction = 0;
	flags = 0;

	//
	//	Create a top level symbol table if one is not provided for variables and
	//	procs. Variables may create other symbol tables for block level
	//	declarations so we use mprAllocLockedHandle to manage a list of variable
	//	tables.
	// 
	vars = (MprHashTable**) mprMalloc(LOCAL_VAR_CHUNK_SIZE * 
		sizeof(MprHashTable));
	vmax = LOCAL_VAR_CHUNK_SIZE;

	if (varTable == 0) {
		vars[0] = new MprHashTable(61);
		flags |= EJS_FLAGS_VARIABLES;

	} else {
		vars[0] = varTable;
	}
	vid = 0;

	if (procTable == 0) {
		procs = new MprHashTable(61);
		flags |= EJS_FLAGS_FUNCTIONS;
	} else {
		procs = procTable;
	}

	lex = new MprEjsLex(this);
	setGlobalVar("null", 0);
}

////////////////////////////////////////////////////////////////////////////////

MprEjs::~MprEjs()
{
	int		i;

	if (errorMsg) {
		mprFree(errorMsg);
	}
	mprFree(result);

	delete lex;

	//
	//	If the global vars were allocated, free them, then free any
	//	local variable spaces that are left around
	// 
	if (flags & EJS_FLAGS_VARIABLES) {
#if OLD
		hp = vars[0]->getFirst();
		while (hp) {
			mprFree(hp->getValue());
			hp = vars[0]->getNext(hp);
		}
#endif
		delete vars[0];
	}
	// FUTURE: -- Should this be vid or vmax 
	for (i = 1; i <= vid; i++) {
#if OLD
		hp = vars[i]->getFirst(&index);
		while (hp) {
			mprFree(hp->getValue());
			hp = vars[i]->getNext(hp, &index);
		}
#endif
		delete vars[i];
	}
	mprFree(vars);

	if (flags & EJS_FLAGS_FUNCTIONS) {
		delete procs;
	}
}

////////////////////////////////////////////////////////////////////////////////

char *MprEjs::evalScriptFile(char *path, char **emsg)
{
	struct stat sbuf;
	char		*rs;
	char		*fileBuf;
	int			fd;

	mprAssert(path && *path);

	if (emsg) {
		*emsg = 0;
	}

	if ((fd = open(path, O_RDONLY | O_BINARY, 0666)) < 0) {
		error("Bad handle %d");
		return 0;
	}

	if (stat(path, &sbuf) < 0) {
		close(fd);
		error("Cant stat %s", path);
		return 0;
	}

	fileBuf = (char*) mprMalloc(sbuf.st_size + 1);
	if (read(fd, fileBuf, sbuf.st_size) != (int)sbuf.st_size) {
		close(fd);
		mprFree(fileBuf);
		error("Error reading %s", path);
		return 0;
	}
	fileBuf[sbuf.st_size] = '\0';
	close(fd);

	rs = evalScriptBlock(fileBuf, emsg);

	mprFree(fileBuf);
	return rs;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Create a new variable scope block so that consecutive evalScript
//	calls may be made with the same (local) varible scope. This space MUST be
//	closed with closeBlock when the evaluations are complete.
// 

int MprEjs::openBlock()
{
	if (++vid >= vmax) {
		vmax += LOCAL_VAR_CHUNK_SIZE;
		mprRealloc(vars, vmax * sizeof(MprHashTable*));
	}
	vars[vid] = new MprHashTable(61);
	return vid;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Close the topmost variable scope block.
// 

int MprEjs::closeBlock()
{
	delete vars[vid--];
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Create a new variable scope block and evaluate a script. All variables
//	created during this context will be automatically deleted when complete.
// 

char *MprEjs::evalScriptBlock(char *script, char **emsg)
{
	char	*returnVal;

	mprAssert(script);

	openBlock();
	returnVal = evalScript(script, emsg);
	closeBlock();

	return returnVal;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Parse and evaluate a JavaScript. The caller may provide a symbol table to
//	use for variables and function definitions. Return char pointer on
//	success otherwise NULL pointer is returned.
// 

char *MprEjs::evalScript(char *script, char **emsg)
{
	MprEjsInput	*ip, *oldBlock;
	int			state;
	char		*endlessLoopTest;
	int			loopCounter;
	
	mprAssert(script);

	setString(&result, "");

	//
	//	Allocate a new evaluation block, and save the old one
	// 
	oldBlock = lex->ip;
	lex->openScript(script);

	ip = lex->ip;
	if (emsg) {
		*emsg = 0;
	} 

	//
	//	Do the actual parsing and evaluation
	// 
	loopCounter = 0;
	endlessLoopTest = 0;

	do {
		state = parse(EJS_STATE_BEGIN, EJS_FLAGS_EXE);

		if (state == EJS_STATE_RET) {
			state = EJS_STATE_EOF;
		}
		//
		//	prevent parser from going into infinite loop.  If parsing the same
		//	line 10 times then fail and report a Syntax error.  
		//	are caught in the parser itself.
		// 
		if (endlessLoopTest == ip->script.getStart()) {
			if (loopCounter++ > 10) {
				state = EJS_STATE_ERR;
				error("Syntax error");
			}
		} else {
			endlessLoopTest = ip->script.getStart();
			loopCounter = 0;
		}

	} while (state != EJS_STATE_EOF && state != EJS_STATE_ERR);

	lex->closeScript();

	//
	//	Return any error string to the user
	// 
	if (state == EJS_STATE_ERR && emsg) {
		*emsg = mprStrdup(errorMsg);
	}

	//
	//	Restore the old evaluation block
	// 
	lex->ip = oldBlock;

	if (state == EJS_STATE_EOF) {
		return result;
	}

	if (state == EJS_STATE_ERR) {
		return 0;
	}
	return result;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Recursive descent parser for JavaScript
// 

int MprEjs::parse(int state, int flags)
{
	switch (state) {
	//
	//	Any statement, function arguments or conditional expressions
	// 
	case EJS_STATE_STMT:
		if ((state = parseStmt(state, flags)) != EJS_STATE_STMT_DONE &&
			state != EJS_STATE_EOF && state != EJS_STATE_STMT_BLOCK_DONE &&
			state != EJS_STATE_RET) {
			state = EJS_STATE_ERR;
		}
		break;

	case EJS_STATE_DEC:
		if ((state = parseStmt(state, flags)) != EJS_STATE_DEC_DONE &&
			state != EJS_STATE_EOF) {
			state = EJS_STATE_ERR;
		}
		break;

	case EJS_STATE_EXPR:
		if ((state = parseStmt(state, flags)) != EJS_STATE_EJS_EXPR_DONE &&
			state != EJS_STATE_EOF) {
			state = EJS_STATE_ERR;
		}
		break;

	//
	//	Variable declaration list
	// 
	case EJS_STATE_DEC_LIST:
		state = parseDeclaration(state, flags);
		break;

	//
	//	Function argument string
	// 
	case EJS_STATE_ARG_LIST:
		state = parseArgList(state, flags);
		break;

	//
	//	Logical condition list (relational operations separated by &&, ||)
	// 
	case EJS_STATE_COND:
		state = parseCond(state, flags);
		break;

	//
	//	Expression list
	// 
	case EJS_STATE_RELEXP:
		state = parseExpr(state, flags);
		break;
	}

	if (state == EJS_STATE_ERR && errorMsg == 0) {
		error("Syntax error");
	}
	return state;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Parse any statement including functions and simple relational operations
// 

int MprEjs::parseStmt(int state, int flags)
{
	MprEjsFunction	*function;
	MprEjsFunction	*saveFunc;
	MprEjsSaveInput	condScript, endScript, bodyScript, incrScript;
	char			*value, *id;
	int				done, expectSemi, thenFlags, elseFlags, tid, cond, forFlags;
	int				jsVarType;

	expectSemi = 0;
	saveFunc = 0;

	for (done = 0; !done; ) {
		tid = lex->getToken(state);

		switch (tid) {
		default:
			lex->putbackToken(EJS_TOK_EXPR, lex->token);
			done++;
			break;

		case EJS_TOK_ERR:
			state = EJS_STATE_ERR;
			done++;
			break;

		case EJS_TOK_EOF:
			state = EJS_STATE_EOF;
			done++;
			break;

		case EJS_TOK_NEWLINE:
			break;

		case EJS_TOK_SEMI:
			//
			//	This case is when we discover no statement and just a lone ';'
			// 
			if (state != EJS_STATE_STMT) {
				lex->putbackToken(tid, lex->token);
			}
			done++;
			break;

		case EJS_TOK_ID:
			//
			//	This could either be a reference to a variable or an assignment
			// 
			id = 0;
			setString(&id, lex->token);
			//
			//	Peek ahead to see if this is an assignment
			// 
			tid = lex->getToken(state);
			if (tid == EJS_TOK_ASSIGNMENT) {
				if (parse(EJS_STATE_RELEXP, flags) != EJS_STATE_RELEXP_DONE) {
					clearString(&id);
					goto err;
				}
				if (flags & EJS_FLAGS_EXE) {
					if (state == EJS_STATE_DEC) {
						setVar(id, result);
					} else {
						jsVarType = getVar(id, &value);
						if (jsVarType > 0) {
							setVar(id, result);
						} else {
							setGlobalVar(id, result);
						}
					}
				}

			} else if (tid == EJS_TOK_INC_DEC ) {
				value = 0;
				if (flags & EJS_FLAGS_EXE) {
					jsVarType = getVar(id, &value);
					if (jsVarType < 0) {
						error("Undefined variable %s\n", id);
						goto err;
					}
					setString(&result, value);
					if (evalExpr(value, (int) *lex->token, "1") < 0) {
						state = EJS_STATE_ERR;
						break;
					}

					if (jsVarType > 0) {
						setVar(id, result);
					} else {
						setGlobalVar(id, result);
					}
				}

			} else {
				//
				//	If we are processing a declaration, allow undefined vars
				// 
				value = 0;
				if (state == EJS_STATE_DEC) {
					if (getVar(id, &value) > 0) {
						error("Variable already declared", id);
						clearString(&id);
						goto err;
					}
					setVar(id, 0);

				} else {
					if (flags & EJS_FLAGS_EXE) {
						//
						//	Allow accesses to undefined variables to return ""
						//
						if (getVar(id, &value) < 0) {
							// error("Undefined variable %s\n", id);
							clearString(&id);
							// goto err;
						}
					}
				}
				setString(&result, value);
				lex->putbackToken(tid, lex->token);
			}
			clearString(&id);

			if (state == EJS_STATE_STMT) {
				expectSemi++;
			}
			done++;
			break;

		case EJS_TOK_LITERAL:
			//
			//	Set the result to the literal (number or string constant)
			// 
			setString(&result, lex->token);
			if (state == EJS_STATE_STMT) {
				expectSemi++;
			}
			done++;
			break;

		case EJS_TOK_FUNCTION:
			//
			//	We must save any current func value for the current frame
			// 
			if (currentFunction) {
				saveFunc = currentFunction;
			}
			function = new MprEjsFunction(lex->token);
			currentFunction = function;

			setString(&result, "");
			if (lex->getToken(state) != EJS_TOK_LPAREN) {
				delete function;
				currentFunction = saveFunc;
				goto err;
			}

			if (parse(EJS_STATE_ARG_LIST, flags) != EJS_STATE_ARG_LIST_DONE) {
				delete function;
				currentFunction = saveFunc;
				goto err;
			}
			//
			//	Evaluate the function if required
			// 
			if (flags & EJS_FLAGS_EXE && evalFunction() < 0) {
				delete function;
				currentFunction = saveFunc;
				goto err;
			}

			delete function;
			currentFunction = saveFunc;

			if (lex->getToken(state) != EJS_TOK_RPAREN) {
				goto err;
			}
			if (state == EJS_STATE_STMT) {
				expectSemi++;
			}
			done++;
			break;

		case EJS_TOK_IF:
			if (state != EJS_STATE_STMT) {
				goto err;
			}
			if (lex->getToken(state) != EJS_TOK_LPAREN) {
				goto err;
			}
			//
			//	Evaluate the entire condition list "(condition)"
			// 
			if (parse(EJS_STATE_COND, flags) != EJS_STATE_EJS_COND_DONE) {
				goto err;
			}
			if (lex->getToken(state) != EJS_TOK_RPAREN) {
				goto err;
			}
			//
			//	This is the "then" case. We need to always parse both cases and
			//	execute only the relevant case.
			// 
			if (*result == '1') {
				thenFlags = flags;
				elseFlags = flags & ~EJS_FLAGS_EXE;
			} else {
				thenFlags = flags & ~EJS_FLAGS_EXE;
				elseFlags = flags;
			}
			//
			//	Process the "then" case.  Allow for RETURN statement
			// 
			switch (parse(EJS_STATE_STMT, thenFlags)) {
			case EJS_STATE_RET:
				return EJS_STATE_RET;
			case EJS_STATE_STMT_DONE:
				break;
			default:
				goto err;
			}
			//
			//	Check to see if there is an "else" case
			// 
			eatNewLines(state);
			tid = lex->getToken(state);
			if (tid != EJS_TOK_ELSE) {
				lex->putbackToken(tid, lex->token);
				done++;
				break;
			}
			//
			//	Process the "else" case.  Allow for return.
			// 
			switch (parse(EJS_STATE_STMT, elseFlags)) {
			case EJS_STATE_RET:
				return EJS_STATE_RET;
			case EJS_STATE_STMT_DONE:
				break;
			default:
				goto err;
			}
			done++;
			break;

		case EJS_TOK_FOR:
			//
			//	Format for the expression is:
			//
			//		for (initial; condition; incr) {
			//			body;
			//		}
			// 
			if (state != EJS_STATE_STMT) {
				goto err;
			}
			if (lex->getToken(state) != EJS_TOK_LPAREN) {
				goto err;
			}

			//
			//	Evaluate the for loop initialization statement
			// 
			if (parse(EJS_STATE_EXPR, flags) != EJS_STATE_EJS_EXPR_DONE) {
				goto err;
			}
			if (lex->getToken(state) != EJS_TOK_SEMI) {
				goto err;
			}

			//
			//	The first time through, we save the current input context just
			//	prior to each step: prior to the conditional, the loop 
			//	increment and the loop body.
			//
			lex->ip->saveInputState(&condScript);
			if (parse(EJS_STATE_COND, flags) != EJS_STATE_EJS_COND_DONE) {
				goto err;
			}
			cond = (*result != '0');

			if (lex->getToken(state) != EJS_TOK_SEMI) {
				goto err;
			}

			//
			//	Don't execute the loop increment statement or the body first 
			//	time
			//
			forFlags = flags & ~EJS_FLAGS_EXE;
			lex->ip->saveInputState(&incrScript);
			if (parse(EJS_STATE_EXPR, forFlags) != EJS_STATE_EJS_EXPR_DONE) {
				goto err;
			}
			if (lex->getToken(state) != EJS_TOK_RPAREN) {
				goto err;
			}

			//
			//	Parse the body and remember the end of the body script
			// 
			lex->ip->saveInputState(&bodyScript);
			if (parse(EJS_STATE_STMT, forFlags) != EJS_STATE_STMT_DONE) {
				goto err;
			}
			lex->ip->saveInputState(&endScript);

			//
			//	Now actually do the for loop. Note loop has been rotated
			// 
			while (cond && (flags & EJS_FLAGS_EXE) ) {
				//
				//	Evaluate the body
				// 
				lex->ip->restoreInputState(&bodyScript);

				switch (parse(EJS_STATE_STMT, flags)) {
				case EJS_STATE_RET:
					return EJS_STATE_RET;
				case EJS_STATE_STMT_DONE:
					break;
				default:
					goto err;
				}
				//
				//	Evaluate the increment script
				// 
				lex->ip->restoreInputState(&incrScript);
				if (parse(EJS_STATE_EXPR, flags) != EJS_STATE_EJS_EXPR_DONE) {
					goto err;
				}
				//
				//	Evaluate the condition
				// 
				lex->ip->restoreInputState(&condScript);
				if (parse(EJS_STATE_COND, flags) != EJS_STATE_EJS_COND_DONE) {
					goto err;
				}
				cond = (*result != '0');
			}
			lex->ip->restoreInputState(&endScript);
			done++;
			break;

		case EJS_TOK_VAR:
			if (parse(EJS_STATE_DEC_LIST, flags) != EJS_STATE_DEC_LIST_DONE) {
				goto err;
			}
			done++;
			break;

		case EJS_TOK_COMMA:
			lex->putbackToken(EJS_TOK_EXPR, lex->token);
			done++;
			break;

		case EJS_TOK_LPAREN:
			if (state == EJS_STATE_EXPR) {
				if (parse(EJS_STATE_RELEXP, flags) != EJS_STATE_RELEXP_DONE) {
					goto err;
				}
				if (lex->getToken(state) != EJS_TOK_RPAREN) {
					goto err;
				}
				return EJS_STATE_EJS_EXPR_DONE;
			}
			done++;
			break;

		case EJS_TOK_RPAREN:
			lex->putbackToken(tid, lex->token);
			return EJS_STATE_EJS_EXPR_DONE;

		case EJS_TOK_LBRACE:
			//
			//	This handles any code in braces except "if () {} else {}"
			// 
			if (state != EJS_STATE_STMT) {
				goto err;
			}

			//
			//	Parse returns EJS_STATE_STMT_BLOCK_DONE when the RBRACE is seen
			// 
			do {
				state = parse(EJS_STATE_STMT, flags);
			} while (state == EJS_STATE_STMT_DONE);

			//
			//	Allow return statement.
			// 
			if (state == EJS_STATE_RET) {
				return state;
			}

			if (lex->getToken(state) != EJS_TOK_RBRACE) {
				goto err;
			}
			return EJS_STATE_STMT_DONE;

		case EJS_TOK_RBRACE:
			if (state == EJS_STATE_STMT) {
				lex->putbackToken(tid, lex->token);
				return EJS_STATE_STMT_BLOCK_DONE;
			}
			goto err;

		case EJS_TOK_RETURN:
			if (parse(EJS_STATE_RELEXP, flags) != EJS_STATE_RELEXP_DONE) {
				goto err;
			}
			if (flags & EJS_FLAGS_EXE) {
				while (lex->getToken(state) != EJS_TOK_EOF )
					;
				done++;
				return EJS_STATE_RET;
			}
			break;
		}
	}

	if (expectSemi) {
		tid = lex->getToken(state);
		if (tid != EJS_TOK_SEMI && tid != EJS_TOK_NEWLINE) {
			goto err;
		}

		//
		//	Skip newline after semi-colon
		// 
		eatNewLines(state);
	}

	//
	//	Free resources and return the correct status
	// 

doneParse:
	if (tid == EJS_TOK_FOR) {
		lex->ip->freeInputState(&condScript);
		lex->ip->freeInputState(&incrScript);
		lex->ip->freeInputState(&endScript);
		lex->ip->freeInputState(&bodyScript);
	}

	if (state == EJS_STATE_STMT) {
		return EJS_STATE_STMT_DONE;
	} else if (state == EJS_STATE_DEC) {
		return EJS_STATE_DEC_DONE;
	} else if (state == EJS_STATE_EXPR) {
		return EJS_STATE_EJS_EXPR_DONE;
	} else if (state == EJS_STATE_EOF) {
		return state;
	} else {
		return EJS_STATE_ERR;
	}

//
//	Common error exit
// 
err:
	state = EJS_STATE_ERR;
	goto doneParse;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Parse variable declaration list
// 

int MprEjs::parseDeclaration(int state, int flags)
{
	int		tid;

	//
	//	Declarations can be of the following forms:
	//			var x;
	//			var x, y, z;
	//			var x = 1 + 2 / 3, y = 2 + 4;
	//
	//	We set the variable to NULL if there is no associated assignment.
	// 

	do {
		if ((tid = lex->getToken(state)) != EJS_TOK_ID) {
			return EJS_STATE_ERR;
		}
		lex->putbackToken(tid, lex->token);

		//
		//	Parse the entire assignment or simple identifier declaration
		// 
		if (parse(EJS_STATE_DEC, flags) != EJS_STATE_DEC_DONE) {
			return EJS_STATE_ERR;
		}

		//
		//	Peek at the next token, continue if comma seen
		// 
		tid = lex->getToken(state);
		if (tid == EJS_TOK_SEMI) {
			return EJS_STATE_DEC_LIST_DONE;
		} else if (tid != EJS_TOK_COMMA) {
			return EJS_STATE_ERR;
		}
	} while (tid == EJS_TOK_COMMA);

	if (tid != EJS_TOK_SEMI) {
		return EJS_STATE_ERR;
	}
	return EJS_STATE_DEC_LIST_DONE;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Parse function arguments
// 

int MprEjs::parseArgList(int state, int flags)
{
	int		tid;

	do {
		state = parse(EJS_STATE_RELEXP, flags);
		if (state == EJS_STATE_EOF || state == EJS_STATE_ERR) {
			return state;
		}
		//
		//	We store in the hlist a direct pointer to each arg. This is really
		//	then an argv list. FUTURE -- remove Argv for speed !!!!
		// 
		if (state == EJS_STATE_RELEXP_DONE) {
			currentFunction->insertArg(result);
		}
		//
		//	Peek at the next token, continue if more args (ie. comma seen)
		// 
		tid = lex->getToken(state);
		if (tid != EJS_TOK_COMMA) {
			lex->putbackToken(tid, lex->token);
		}
	} while (tid == EJS_TOK_COMMA);

	if (tid != EJS_TOK_RPAREN && state != EJS_STATE_RELEXP_DONE) {
		return EJS_STATE_ERR;
	}
	return EJS_STATE_ARG_LIST_DONE;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Parse conditional expression (relational ops separated by ||, &&)
// 

int MprEjs::parseCond(int state, int flags)
{
	char	*lhs, *rhs;
	int		tid, op;

	setString(&result, "");
	rhs = lhs = 0;
	op = 0;

	do {
		//
		//	Recurse to handle one side of a conditional. Accumulate the
		//	left hand side and the final result in result.
		// 
		state = parse(EJS_STATE_RELEXP, flags);
		if (state != EJS_STATE_RELEXP_DONE) {
			state = EJS_STATE_ERR;
			break;
		}

		if (op > 0) {
			setString(&rhs, result);
			if (evalCond(lhs, op, rhs) < 0) {
				state = EJS_STATE_ERR;
				break;
			}
		}
		setString(&lhs, result);

		tid = lex->getToken(state);
		if (tid == EJS_TOK_LOGICAL) {
			op = (int) *lex->token;

		} else if (tid == EJS_TOK_RPAREN || tid == EJS_TOK_SEMI) {
			lex->putbackToken(tid, lex->token);
			state = EJS_STATE_EJS_COND_DONE;
			break;

		} else {
			lex->putbackToken(tid, lex->token);
		}

	} while (state == EJS_STATE_RELEXP_DONE);

	if (lhs) {
		mprFree(lhs);
	}

	if (rhs) {
		mprFree(rhs);
	}
	return state;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Parse expression (leftHandSide operator rightHandSide)
// 

int MprEjs::parseExpr(int state, int flags)
{
	char	*lhs, *rhs;
	int		rel, tid;

	setString(&result, "");
	rhs = lhs = 0;
	rel = 0;
	tid = 0;

	do {
		//
		//	This loop will handle an entire expression list. We call parse
		//	to evalutate each term which returns the result in "this->result".
		// 
		if (tid == EJS_TOK_LOGICAL) {
			state = parse(EJS_STATE_RELEXP, flags);
			if (state != EJS_STATE_RELEXP_DONE) {
				state = EJS_STATE_ERR;
				break;
			}
		} else {
			state = parse(EJS_STATE_EXPR, flags);
			if (state != EJS_STATE_EJS_EXPR_DONE) {
				state = EJS_STATE_ERR;
				break;
			}
		}
		if (rel > 0) {
			setString(&rhs, result);
			if (tid == EJS_TOK_LOGICAL) {
				if (evalCond(lhs, rel, rhs) < 0) {
					state = EJS_STATE_ERR;
					break;
				}
			} else {
				if (evalExpr(lhs, rel, rhs) < 0) {
					state = EJS_STATE_ERR;
					break;
				}
			}
		}
		setString(&lhs, result);

		if ((tid = lex->getToken(state)) == EJS_TOK_EXPR ||
			 tid == EJS_TOK_INC_DEC || tid == EJS_TOK_LOGICAL) {
			rel = (int) *lex->token;

		} else {
			lex->putbackToken(tid, lex->token);
			state = EJS_STATE_RELEXP_DONE;
		}

	} while (state == EJS_STATE_EJS_EXPR_DONE);

	if (rhs) {
		mprFree(rhs);
	}
	if (lhs) {
		mprFree(lhs);
	}
	return state;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Evaluate a condition. Implements &&, ||, !
// 

int MprEjs::evalCond(char *lhs, int rel, char *rhs)
{
	int		l, r, lval;

	mprAssert(lhs);
	mprAssert(rhs);
	mprAssert(rel > 0);

	lval = 0;
	if ((isdigit((int)*lhs) || *lhs == '-') &&
		(isdigit((int)*rhs) || *rhs == '-')) {
		l = atoi(lhs);
		r = atoi(rhs);
		switch (rel) {
		case EJS_COND_AND:
			lval = l && r;
			break;
		case EJS_COND_OR:
			lval = l || r;
			break;
		default:
			error("Bad operator %d", rel);
			return -1;
		}
	} else {
		if (!isdigit((int)*lhs) && *lhs != '-') {
			error("Conditional must be numeric", lhs);
		} else {
			error("Conditional must be numeric", rhs);
		}
	}

	if (lval < 0) {
		setString(&result, "-1");
	} else if (lval == 0) {
		setString(&result, "0");
	} else {
		setString(&result, "1");
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Evaluate an operation
// 

int MprEjs::evalExpr(char *lhs, int rel, char *rhs)
{
	char	*cp, numBuf[16];
	int		numeric, l, r, lval;

	mprAssert(lhs);
	mprAssert(rhs);
	mprAssert(rel > 0);

	//
	//	All of the characters in the lhs and rhs must be numeric
	// 
	numeric = 1;
	for (cp = lhs; *cp; cp++) {
		if (!isdigit((int)*cp) && *cp != '-') {
			numeric = 0;
			break;
		}
	}
	if (numeric) {
		for (cp = rhs; *cp; cp++) {
			if (!isdigit((int)*cp) && *cp != '-') {
				numeric = 0;
				break;
			}
		}
	}
	if (numeric) {
		l = atoi(lhs);
		r = atoi(rhs);
		switch (rel) {
		case EJS_EXPR_PLUS:
			lval = l + r;
			break;
		case EJS_EXPR_INC:
			lval = l + 1;
			break;
		case EJS_EXPR_MINUS:
			lval = l - r;
			break;
		case EJS_EXPR_DEC:
			lval = l - 1;
			break;
		case EJS_EXPR_MUL:
			lval = l * r;
			break;
		case EJS_EXPR_DIV:
			if (r != 0) {
				lval = l / r;
			} else {
				lval = 0;
			}
			break;
		case EJS_EXPR_MOD:
			if (r != 0) {
				lval = l % r;
			} else {
				lval = 0;
			}
			break;
		case EJS_EXPR_LSHIFT:
			lval = l << r;
			break;
		case EJS_EXPR_RSHIFT:
			lval = l >> r;
			break;
		case EJS_EXPR_EQ:
			lval = l == r;
			break;
		case EJS_EXPR_NOTEQ:
			lval = l != r;
			break;
		case EJS_EXPR_LESS:
			lval = (l < r) ? 1 : 0;
			break;
		case EJS_EXPR_LESSEQ:
			lval = (l <= r) ? 1 : 0;
			break;
		case EJS_EXPR_GREATER:
			lval = (l > r) ? 1 : 0;
			break;
		case EJS_EXPR_GREATEREQ:
			lval = (l >= r) ? 1 : 0;
			break;
		case EJS_EXPR_BOOL_COMP:
			lval = (r == 0) ? 1 : 0;
			break;
		default:
			error("Bad operator %d", rel);
			return -1;
		}

	} else {
		switch (rel) {
		case EJS_EXPR_PLUS:
			clearString(&result);
			appendString(&result, lhs);
			appendString(&result, rhs);
			return 0;
		case EJS_EXPR_LESS:
			lval = strcmp(lhs, rhs) < 0;
			break;
		case EJS_EXPR_LESSEQ:
			lval = strcmp(lhs, rhs) <= 0;
			break;
		case EJS_EXPR_GREATER:
			lval = strcmp(lhs, rhs) > 0;
			break;
		case EJS_EXPR_GREATEREQ:
			lval = strcmp(lhs, rhs) >= 0;
			break;
		case EJS_EXPR_EQ:
			lval = strcmp(lhs, rhs) == 0;
			break;
		case EJS_EXPR_NOTEQ:
			lval = strcmp(lhs, rhs) != 0;
			break;
		case EJS_EXPR_INC:
		case EJS_EXPR_DEC:
		case EJS_EXPR_MINUS:
		case EJS_EXPR_DIV:
		case EJS_EXPR_MOD:
		case EJS_EXPR_LSHIFT:
		case EJS_EXPR_RSHIFT:
		default:
			error("Bad operator");
			return -1;
		}
	}

#if OLD_BUGGED_CODE
	if (lval < 0) {
		setString(&result, "-1");
	} else if (lval == 0) {
		setString(&result, "0");
	} else {
		setString(&result, "1");
	}
#endif
	setString(&result, mprItoa(lval, numBuf, sizeof(numBuf)));
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Evaluate a function
// 

int MprEjs::evalFunction()
{
	MprEjsProc*	proc;
	MprEjs*		oldEjs;
	int			rc;

	proc = (MprEjsProc*) procs->lookup(currentFunction->name);
	if (proc == 0) {
		proc = (MprEjsProc*) 
			jsService->stndProcs->lookup(currentFunction->name);
		if (proc == 0) {
			error("Undefined procedure %s", currentFunction->name);
			return MPR_ERR_NOT_FOUND;
		}
	}
	oldEjs = (MprEjs*) proc->getScriptEngine();
	proc->setScriptEngine(this);
	rc = proc->run((void*) userHandle, currentFunction->argc, 
		currentFunction->argv);
	proc->setScriptEngine(oldEjs);
	return rc;
}

////////////////////////////////////////////////////////////////////////////////

void MprEjs::error(char *fmt, ...)
{
	va_list		args;
	char		*errbuf, *msgbuf;

	mprAssert(fmt);

	va_start(args, fmt);
	msgbuf = 0;
	mprAllocVsprintf(&msgbuf, MPR_MAX_STRING, fmt, args);
	va_end(args);

	if (lex->ip != 0) {
		mprAllocSprintf(&errbuf, MPR_MAX_STRING,
			"%s at line %d, offending line: \n%s\n", 
			msgbuf, lex->ip->lineNumber, lex->ip->line);
		mprFree(errorMsg);
		errorMsg = errbuf;
	}
	mprFree(msgbuf);
}

////////////////////////////////////////////////////////////////////////////////
//
//	Append to the pointer value
// 

void MprEjs::appendString(char **ptr, char *s)
{
	int	len, oldlen;

	mprAssert(ptr);

	if (*ptr) {
		len = strlen(s);
		oldlen = strlen(*ptr);
		*ptr = (char*) mprRealloc(*ptr, (len + oldlen + 1) * sizeof(char));
		strcpy(&(*ptr)[oldlen], s);
	} else {
		*ptr = mprStrdup(s);
	}
}

////////////////////////////////////////////////////////////////////////////////
//
//	Define a procedure
// 

void MprEjs::insertProc(MprEjsProc *proc)
{
	procs->insert(proc);
}

////////////////////////////////////////////////////////////////////////////////
//
//	Remove ("undefine") a procedure
// 

void MprEjs::removeProc(char *name)
{
	procs->remove(name);
}

////////////////////////////////////////////////////////////////////////////////
//
//	Get a procedure definition
// 

MprEjsProc *MprEjs::getProc(char *name)
{
	MprEjsProc*		proc;

	if ((proc = (MprEjsProc*) procs->lookup(name)) == 0) {
		proc = (MprEjsProc*) jsService->stndProcs->lookup(name);
		if (proc == 0) {
			return 0;
		}
	}
	return proc;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Define the user handle
// 

void MprEjs::setUserHandle(void *handle)
{
	userHandle = handle;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Get the user handle
// 

void *MprEjs::getUserHandle()
{
	return userHandle;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Get the current line number
// 

int MprEjs::getLineNumber()
{
	return lex->ip->lineNumber;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Set the result
// 

void MprEjs::setResult(char *s)
{
	setString(&result, s);
}

////////////////////////////////////////////////////////////////////////////////
//
//	Get the result
// 

char *MprEjs::getResult()
{
	return result;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Set a local variable. Note: a variable with a value of NULL means declared 
//	but undefined. The value is defined in the top-most variable frame.
// 

void MprEjs::setVar(char *var, char *value)
{
	mprAssert(var && *var);

	vars[vid]->insert(new MprStringHashEntry(var, value));
}

////////////////////////////////////////////////////////////////////////////////
//
//	Set a global variable. Note: a variable with a value of NULL means
//	declared but undefined. The value is defined in the global variable frame.
// 

void MprEjs::setGlobalVar(char *var, char *value)
{
	mprAssert(var);

	vars[0]->insert(new MprStringHashEntry(var, value));
}

////////////////////////////////////////////////////////////////////////////////
//
//	Get a variable
//	Returns > 0 if the variable is found in the current local var space
//	Returns 0 if the variable is global
//	Returns -1 of var not found.
// 

int MprEjs::getVar(char *var, char **value)
{
	MprStringHashEntry	*hp;
	int					scope;

	mprAssert(var && *var);
	mprAssert(value);

	//
	//	Look in the current local space and the global one if that fails
	//	Intermediate var spaces are not examined
	//	As a last resort, look in the environment var space for the variable
	//
	scope = vid;
	if ((hp = (MprStringHashEntry*) vars[scope]->lookup(var)) == 0) {
		if ((hp = (MprStringHashEntry*) vars[0]->lookup(var)) == 0) {
			if ((hp = (MprStringHashEntry*) jsService->stndVars->lookup(var)) 
					== 0) {
				return MPR_ERR_NOT_FOUND;
			}
		}
		scope = 0;
	}
	*value = hp->getValue();
	return scope;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Get the variable symbol table
//	Use caution with the returned value, it may not be threadsafe to use
// 

MprHashTable *MprEjs::getVariableTable()
{
	return vars[0];
}

////////////////////////////////////////////////////////////////////////////////
//
//	Get the procs symbol table
// 

MprHashTable *MprEjs::getProcTable()
{
	return procs;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Set the procs symbol table for an EJ space
//	Return the old value for the procs table, -1 on error
// 

MprHashTable *MprEjs::setProcTable(MprHashTable *procTable)
{
	MprHashTable		*oldProcs;

	oldProcs = procs;
	procs = procTable;
	return oldProcs;
}

////////////////////////////////////////////////////////////////////////////////
//
//	This function removes any new lines.  Used for else	cases, etc.
// 

void MprEjs::eatNewLines(int state)
{
	int tid;

	do {
		tid = lex->getToken(state);
	} while (tid == EJS_TOK_NEWLINE);

	lex->putbackToken(tid, lex->token);
}

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// MprEjsFunction ////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MprEjsFunction::MprEjsFunction(char *name)
{
	this->name = mprStrdup(name);
	argv = (char**) mprMalloc(EJS_DEFAULT_ARGC * sizeof(char*));
	argvSize = EJS_DEFAULT_ARGC;
	argc = 0;
}

////////////////////////////////////////////////////////////////////////////////

MprEjsFunction::~MprEjsFunction()
{
	int		i;

	mprFree(name);
	for (i = 0 ; i < argc; i++) {
		mprFree(argv[i]);
	}
	mprFree(argv);
}

////////////////////////////////////////////////////////////////////////////////

void MprEjsFunction::insertArg(char *result)
{
	if (argc < argvSize) {
		argv[argc++] = mprStrdup(result);
	} else {
		argvSize += EJS_DEFAULT_ARGC;
		argv = (char**) mprRealloc(argv, argvSize * sizeof(char*));
	}
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//	Utility routine to crack JavaScript arguments. Return the number of args
//	seen. This routine only supports %s and %d type args.
//
//	Typical usage:
//
//		if (mprParseArgs(argc, argv, "%s %d", &name, &age) < 2) {
//			mprError("Insufficient args\n");
//			return -1;
//		}
// 

int mprParseArgs(int argc, char **argv, char *fmt, ...)
{
	va_list	vargs;
	bool	*bp;
	char	*cp, **sp;
	int		*ip;
	int		argn;

	va_start(vargs, fmt);

	if (argv == 0) {
		return 0;
	}

	for (argn = 0, cp = fmt; cp && *cp && argn < argc && argv[argn]; ) {
		if (*cp++ != '%') {
			continue;
		}

		switch (*cp) {
		case 'b':
			bp = va_arg(vargs, bool*);
			if (bp) {
				if (mprStrCmpAnyCase(argv[argn], "true") == 0 ||
						argv[argn][0] == '1') {
					*bp = 1;
				} else {
					*bp = 0;
				}
			} else {
				*bp = 0;
			}
			break;

		case 'd':
			ip = va_arg(vargs, int*);
			*ip = atoi(argv[argn]);
			break;

		case 's':
			sp = va_arg(vargs, char**);
			*sp = argv[argn];
			break;

		default:
			mprAssert(0);
		}
		argn++;
	}

	va_end(vargs);
	return argn;
}

////////////////////////////////////////////////////////////////////////////////
#else
void mprEjsDummy() {}

#endif // BLD_FEATURE_EJS_MODULE

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
