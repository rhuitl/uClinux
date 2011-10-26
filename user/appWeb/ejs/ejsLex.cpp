///
///	@file 	lex.cpp
/// @brief 	Javascript lexical analyser
///
///	Embedded JavaScript lexical analyser. This implementes a lexical analyser 
///	for a subset of the JavaScript language.
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

#if BLD_FEATURE_EJS_MODULE
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// MprEjsInput /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MprEjsInput::MprEjsInput() : tokbuf(EJS_INC), script(EJS_SCRIPT_INC)
{
	lineNumber = 1;
	lineLength = 0;
	lineColumn = 0;
	line = 0;

	putBackToken = 0;
	putBackTokenId = -1;
	unaryMinusState = 0;
}

////////////////////////////////////////////////////////////////////////////////

MprEjsInput::~MprEjsInput()
{
	if (putBackToken) {
		mprFree(putBackToken);
	}
	if (line) {
		mprFree(line);
	}
}

////////////////////////////////////////////////////////////////////////////////
#if UNUSED
void MprEjsInput::reset()
{
	line = 0;
	tokbuf.takeBuffer();
	script.takeBuffer();
}
#endif
////////////////////////////////////////////////////////////////////////////////

void MprEjsInput::setScript(char *s)
{
	//
	//	Put the JavaScript into a ring queue for easy parsing
	// 
	script.put(s);
}

////////////////////////////////////////////////////////////////////////////////
//
//	Get another input character
// 

int MprEjsInput::getChar()
{
	int		c, len;

	if ((len = script.getLength()) == 0) {
		return -1;
	}

	c = script.get();

	if (c == '\n') {
		lineNumber++;
		lineColumn = 0;
	} else {
		if ((lineColumn + 2) >= lineLength) {
			lineLength += EJS_INC;
			line = (char*) mprRealloc(line, lineLength * sizeof(char));
		}
		line[lineColumn++] = c;
	}
	line[lineColumn] = '\0';
	return c;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Putback a character onto the input queue
// 

void MprEjsInput::putback(int c)
{
	if (c >= 0) {
		script.insert(c);
		if (--lineColumn < 0) {
			lineColumn = 0;
		}
		line[lineColumn] = '\0';
	}
}

////////////////////////////////////////////////////////////////////////////////
//
//	Save the input state.
// 

void MprEjsInput::saveInputState(MprEjsSaveInput *state)
{
	state->tokbufStart = tokbuf.getStart();
	state->scriptStart = script.getStart();
	if (putBackToken) {
		state->putBackToken = mprStrdup(putBackToken);
	} else {
		state->putBackToken = 0;
	}
	state->putBackTokenId = putBackTokenId;
	state->unaryMinusState = unaryMinusState;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Restore the input state
// 

void MprEjsInput::restoreInputState(MprEjsSaveInput *state)
{
	tokbuf.adjustStart(state->tokbufStart - tokbuf.getStart());
	script.adjustStart(state->scriptStart - script.getStart());

	putBackTokenId = state->putBackTokenId;
	unaryMinusState = state->unaryMinusState;
	if (putBackToken) {
		mprFree(putBackToken);
	}
	if (state->putBackToken) {
		putBackToken = mprStrdup(state->putBackToken);
	} else{
		putBackToken = 0;
	}
}

////////////////////////////////////////////////////////////////////////////////
//
//	Free a saved input state
// 

void MprEjsInput::freeInputState(MprEjsSaveInput *state)
{
	if (state->putBackToken) {
		mprFree(state->putBackToken);
		state->putBackToken = 0;
	}
}

////////////////////////////////////////////////////////////////////////////////
//
//	Convert a hex or octal character back to binary, return original char if 
//	not a hex digit
// 

int MprEjsInput::charConvert(int base, int maxDig)
{
	int	i, c, lval, convChar;

	lval = 0;
	for (i = 0; i < maxDig; i++) {
		if ((c = getChar()) < 0) {
			break;
		}
		//
		//		Initialize to out of range value
		// 
		convChar = base;
		if (isdigit(c)) {
			convChar = c - '0';
		} else if (c >= 'a' && c <= 'f') {
			convChar = c - 'a' + 10;
		} else if (c >= 'A' && c <= 'F') {
			convChar = c - 'A' + 10;
		}
		//
		//	if unexpected character then return it to buffer.
		// 
		if (convChar >= base) {
			putback(c);
			break;
		}
		lval = (lval * base) + convChar;
	}
	return lval;
}

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// MprEjsLex //////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//	Setup the lexical analyser
// 

MprEjsLex::MprEjsLex(MprEjs *ejs)
{
	this->ejs = ejs;
	ip = 0;
	token = 0;
	tokenId = -1;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Close the lexicial analyser
// 

MprEjsLex::~MprEjsLex()
{
}

////////////////////////////////////////////////////////////////////////////////
//
//	Open a new input script
// 

int MprEjsLex::openScript(char *s)
{
	mprAssert(s);

	ip = new MprEjsInput();
	ip->setScript(s);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Close the input script
// 

void MprEjsLex::closeScript()
{
	delete ip;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Get the next JavaScript token
// 

int MprEjsLex::getToken(int state)
{
	tokenId = getLexicalToken(state);
	mprLog(MPR_VERBOSE, "jsGetToken: %d, \"%s\"\n", tokenId, token);
	return tokenId;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Get the next JavaScript token
// 

int MprEjsLex::getLexicalToken(int state)
{
	MprBuf	*inq, *tokq;
	int		done, tid, c, quote, style, c1, unaryMinusState;

	inq = &ip->script;
	tokq = &ip->tokbuf;

	tokenId = -1;
	tid = -1;
	token = "";

	tokq->flush();

	if (ip->putBackTokenId > 0) {
		tokq->put(ip->putBackToken);
		tid = ip->putBackTokenId;
		ip->putBackTokenId = 0;
		if (tid == EJS_TOK_LPAREN || tid == EJS_TOK_EXPR || 
			tid == EJS_TOK_ASSIGNMENT || tid == EJS_TOK_SEMI || 
			tid == EJS_TOK_LOGICAL || tid == EJS_TOK_RETURN) {
			ip->unaryMinusState = EJS_UNARY_MINUS_OK;
		} else {
			ip->unaryMinusState = EJS_UNARY_MINUS_NOT_OK;
		}
		token = tokq->getStart();
		return tid;
	}
	unaryMinusState = ip->unaryMinusState;
	ip->unaryMinusState = EJS_UNARY_MINUS_NOT_OK;

	if ((c = ip->getChar()) < 0) {
		return EJS_TOK_EOF;
	}

	for (done = 0; !done; ) {
		switch (c) {
		case -1:
			ip->unaryMinusState = EJS_UNARY_MINUS_NOT_OK;
			return EJS_TOK_EOF;

		case ' ':
		case '\t':
		case '\r':
			do {
				if ((c = ip->getChar()) < 0)
					break;
			} while (c == ' ' || c == '\t' || c == '\r');
			break;

		case '\n':
			return EJS_TOK_NEWLINE;

		case '(':
			tokenAddChar(c);
			ip->unaryMinusState = EJS_UNARY_MINUS_OK;
			return EJS_TOK_LPAREN;

		case ')':
			tokenAddChar(c);
			return EJS_TOK_RPAREN;

		case '{':
			tokenAddChar(c);
			return EJS_TOK_LBRACE;

		case '}':
			tokenAddChar(c);
			return EJS_TOK_RBRACE;

		case '+':
			if ((c = ip->getChar()) < 0) {
				ejs->error("Syntax Error");
				return EJS_TOK_ERR;
			}
			if (c != '+' ) {
				ip->putback(c);
				tokenAddChar(EJS_EXPR_PLUS);
				ip->unaryMinusState = EJS_UNARY_MINUS_OK;
				return EJS_TOK_EXPR;
			}
			tokenAddChar(EJS_EXPR_INC);
			return EJS_TOK_INC_DEC;

		case '-':
			if ((c = ip->getChar()) < 0) {
				ejs->error("Syntax Error");
				return EJS_TOK_ERR;
			}

			if (c == '-') {
				tokenAddChar(EJS_EXPR_DEC);
				return EJS_TOK_INC_DEC;
			} else if (!isdigit(c) || 
					unaryMinusState == EJS_UNARY_MINUS_NOT_OK) {
				ip->putback(c);
				tokenAddChar(EJS_EXPR_MINUS);
				ip->unaryMinusState = EJS_UNARY_MINUS_OK;
				return EJS_TOK_EXPR;
			}

			//
			//	This is the unary minus case.  Treat the token like a
			//	literal numeric string.
			// 
			if (tokenAddChar('-') < 0) {
				return EJS_TOK_ERR;
			}
			do {
				if (tokenAddChar(c) < 0) {
					return EJS_TOK_ERR;
				}
				if ((c = ip->getChar()) < 0)
					break;
			} while (isdigit(c));
			ip->putback(c);
			return EJS_TOK_LITERAL;

		case '*':
			tokenAddChar(EJS_EXPR_MUL);
			ip->unaryMinusState = EJS_UNARY_MINUS_OK;
			return EJS_TOK_EXPR;

		case '%':
			tokenAddChar(EJS_EXPR_MOD);
			ip->unaryMinusState = EJS_UNARY_MINUS_OK;
			return EJS_TOK_EXPR;

		case '/':
			//
			//	Handle the division operator and comments
			//
			if ((c = ip->getChar()) < 0) {
				ejs->error("Syntax Error");
				return EJS_TOK_ERR;
			}
			if (c != '*' && c != '/') {
				ip->putback(c);
				tokenAddChar(EJS_EXPR_DIV);
				ip->unaryMinusState = EJS_UNARY_MINUS_OK;
				return EJS_TOK_EXPR;
			}
			style = c;
			//
			//	Eat comments. Both C and C++ comment styles are supported.
			//
			while (1) {
				if ((c = ip->getChar()) < 0) {
					ejs->error("Syntax Error");
					return EJS_TOK_ERR;
				}
				if (c == '\n' && style == '/') {
					break;
				} else if (c == '*') {
					c = ip->getChar();
					if (style == '/') {
						if (c == '\n') {
							break;
						}
					} else {
						if (c == '/') {
							break;
						}
					}
				}
			}
			//
			//	Continue looking for a token, so get the next character
			//
			if ((c = ip->getChar()) < 0) {
				return EJS_TOK_EOF;
			}
			break;

		case '<':									// < and <= 
			if ((c = ip->getChar()) < 0) {
				ejs->error("Syntax Error");
				return EJS_TOK_ERR;
			}
			if (c == '<') {
				tokenAddChar(EJS_EXPR_LSHIFT);
				ip->unaryMinusState = EJS_UNARY_MINUS_OK;
				return EJS_TOK_EXPR;
			} else if (c == '=') {
				tokenAddChar(EJS_EXPR_LESSEQ);
				ip->unaryMinusState = EJS_UNARY_MINUS_OK;
				return EJS_TOK_EXPR;
			}
			tokenAddChar(EJS_EXPR_LESS);
			ip->putback(c);
			ip->unaryMinusState = EJS_UNARY_MINUS_OK;
			return EJS_TOK_EXPR;

		case '>':									// > and >= 
			if ((c = ip->getChar()) < 0) {
				ejs->error("Syntax Error");
				return EJS_TOK_ERR;
			}
			if (c == '>') {
				tokenAddChar(EJS_EXPR_RSHIFT);
				ip->unaryMinusState = EJS_UNARY_MINUS_OK;
				return EJS_TOK_EXPR;
			} else if (c == '=') {
				tokenAddChar(EJS_EXPR_GREATEREQ);
				ip->unaryMinusState = EJS_UNARY_MINUS_OK;
				return EJS_TOK_EXPR;
			}
			tokenAddChar(EJS_EXPR_GREATER);
			ip->putback(c);
			ip->unaryMinusState = EJS_UNARY_MINUS_OK;
			return EJS_TOK_EXPR;

		case '=':									// "==" 
			if ((c = ip->getChar()) < 0) {
				ejs->error("Syntax Error");
				return EJS_TOK_ERR;
			}
			if (c == '=') {
				tokenAddChar(EJS_EXPR_EQ);
				ip->unaryMinusState = EJS_UNARY_MINUS_OK;
				return EJS_TOK_EXPR;
			}
			ip->putback(c);
			ip->unaryMinusState = EJS_UNARY_MINUS_OK;
			return EJS_TOK_ASSIGNMENT;

		case '!':									// "!=" or "!"
			if ((c = ip->getChar()) < 0) {
				ejs->error("Syntax Error");
				return EJS_TOK_ERR;
			}
			if (c == '=') {
				tokenAddChar(EJS_EXPR_NOTEQ);
				ip->unaryMinusState = EJS_UNARY_MINUS_OK;
				return EJS_TOK_EXPR;
			}
			ip->putback(c);
			tokenAddChar(EJS_EXPR_BOOL_COMP);
			ip->unaryMinusState = EJS_UNARY_MINUS_OK;
			return EJS_TOK_EXPR;

		case ';':
			tokenAddChar(c);
			ip->unaryMinusState = EJS_UNARY_MINUS_OK;
			return EJS_TOK_SEMI;

		case ',':
			tokenAddChar(c);
			return EJS_TOK_COMMA;

		case '|':									// "||" 
			if ((c = ip->getChar()) < 0 || c != '|') {
				ejs->error("Syntax Error");
				return EJS_TOK_ERR;
			}
			tokenAddChar(EJS_COND_OR);
			ip->unaryMinusState = EJS_UNARY_MINUS_OK;
			return EJS_TOK_LOGICAL;

		case '&':									// "&&" 
			if ((c = ip->getChar()) < 0 || c != '&') {
				ejs->error("Syntax Error");
				return EJS_TOK_ERR;
			}
			tokenAddChar(EJS_COND_AND);
			ip->unaryMinusState = EJS_UNARY_MINUS_OK;
			return EJS_TOK_LOGICAL;

		case '\"':									// String quote 
		case '\'':
			quote = c;
			if ((c = ip->getChar()) < 0) {
				ejs->error("Syntax Error");
				return EJS_TOK_ERR;
			}

			while (c != quote) {
				//
				//	Check for escape sequence characters
				//
				if (c == '\\') {
					c = ip->getChar();

					if (isdigit(c)) {
						//
						//	Octal support, \101 maps to 65 = 'A'. put first char
						//	back so converter will work properly.
						//
						ip->putback(c);
						c = ip->charConvert(EJS_OCTAL, 3);

					} else {
						switch (c) {
						case 'n':
							c = '\n'; break;
						case 'b':
							c = '\b'; break;
						case 'f':
							c = '\f'; break;
						case 'r':
							c = '\r'; break;
						case 't':
							c = '\t'; break;
						case 'x':
							//
							//	Hex support, \x41 maps to 65 = 'A'
							//
							c = ip->charConvert(EJS_HEX, 2);
							break;
						case 'u':
							//
							//	Unicode support, \x0401 maps to 65 = 'A'
							// 
							c = ip->charConvert(EJS_HEX, 2);
							c = c*16 + ip->charConvert(EJS_HEX, 2);

							break;
						case '\'':
						case '\"':
						case '\\':
							break;
						default:
							ejs->error("Invalid Escape Sequence");
							return EJS_TOK_ERR;
						}
					}
					if (tokenAddChar(c) < 0) {
						return EJS_TOK_ERR;
					}
				} else {
					if (tokenAddChar(c) < 0) {
						return EJS_TOK_ERR;
					}
				}
				if ((c = ip->getChar()) < 0) {
					ejs->error("Unmatched Quote");
					return EJS_TOK_ERR;
				}
			}
			return EJS_TOK_LITERAL;

		case '0': case '1': case '2': case '3': case '4': 
		case '5': case '6': case '7': case '8': case '9':
			do {
				if (tokenAddChar(c) < 0) {
					return EJS_TOK_ERR;
				}
				if ((c = ip->getChar()) < 0) {
					break;
				}
			} while (isdigit(c));
			if (c >= 0) {
				ip->putback(c);
			}
			return EJS_TOK_LITERAL;

		default:
			//
			//	Identifiers or a function names
			// 
			while (1) {
				if (c == '\\') {
					//
					//	Just ignore any \ characters.
					//
				} else if (tokenAddChar(c) < 0) {
						break;
				}
				if ((c = ip->getChar()) < 0) {
					break;
				}
				if (!isalnum(c) && c != '$' && c != '_' &&
					c != '\\' && c != ':' && c != '.') {
					break;
				}
			}
			c1 = tokq->look();
			if (! isalpha(c1) && c1 != '$' && c1 != '_' && c1 != ':' && 
					c != '.') {
				ejs->error("Invalid identifier %s", tokq->getStart());
				return EJS_TOK_ERR;
			}
			//
			//	Check for reserved words (only "if", "else", "var", "for"
			//	and "return" at the moment)
			//
			if (state == EJS_STATE_STMT) {
				if (strcmp(token, "if") == 0) {
					return EJS_TOK_IF;
				} else if (strcmp(token, "else") == 0) {
					return EJS_TOK_ELSE;
				} else if (strcmp(token, "var") == 0) {
					return EJS_TOK_VAR;
				} else if (strcmp(token, "for") == 0) {
					return EJS_TOK_FOR;
				} else if (strcmp(token, "return") == 0) {
					if ((c == ';') || (c == '(')) {
						ip->putback(c);
					}
					ip->unaryMinusState = EJS_UNARY_MINUS_OK;
					return EJS_TOK_RETURN;
				}
			}

			// 
			//	Skip white space after token to find out whether this is
			//	a function or not.
 			//
			while (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
				if ((c = ip->getChar()) < 0)
					break;
			}

			tid = (c == '(') ? EJS_TOK_FUNCTION : EJS_TOK_ID;
			done++;
		}
	}

	//
	//	Putback the last extra character for next time
	// 
	ip->putback(c);
	return tid;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Putback the last token read
// 

void MprEjsLex::putbackToken(int tid, char *string)
{
	if (ip->putBackToken) {
		mprFree(ip->putBackToken);
	}
	ip->putBackTokenId = tid;
	ip->putBackToken = mprStrdup(string);
}

////////////////////////////////////////////////////////////////////////////////
//
//	Add a character to the token ringq buffer
// 

int MprEjsLex::tokenAddChar(int c)
{
	if (ip->tokbuf.put((char) c) < 0) {
		ejs->error("Token too big");
		return -1;
	}
	ip->tokbuf.addNull();
	token = ip->tokbuf.getStart();
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
#else
void mprMprEjsLexDummy() {}

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
