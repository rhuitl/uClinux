///
///	 @file   uploadHandler.cpp
///	 @brief  Form-based file upload handler. 
///
///	 "multipart/form-data" content type handler supporting RFC-1867.
///
////////////////////////////////////////////////////////////////////////////////
//
//	  Copyright (c) Mbedthis Software LLC, 2003-2004. All Rights Reserved.
//	  The latest version of this code is available at http://www.mbedthis.com
//
//	  This module was developed on behalf of Guntermann & Drunck GmbH
//	  Systementwicklung, Germany
//
//	  This software is open source; you can redistribute it and/or modify it 
//	  under the terms of the GNU General Public License as published by the 
//	  Free Software Foundation; either version 2 of the License, or (at your 
//	  option) any later version.
//
//	  This program is distributed WITHOUT ANY WARRANTY; without even the 
//	  implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
//	  See the GNU General Public License for more details at:
//	  http://www.mbedthis.com/downloads/gplLicense.html
//	  
//	  This General Public License does NOT permit incorporating this software 
//	  into proprietary programs. If you are unable to comply with the GPL, a 
//	  commercial license for this software and support services are available
//	  from Mbedthis Software at http://www.mbedthis.com
//
//////////////////////////////////// Includes //////////////////////////////////

#include	"uploadHandler.h"

//////////////////////////////////// Locals ////////////////////////////////////
#if BLD_FEATURE_UPLOAD_MODULE

static MaUploadHandlerService *uploadHandlerService;

static char *findSig(void *buf, int buf_length, void *sig, int sigLen);

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// MaUploadModule ////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

int mprUploadInit(void *handle)
{
	new MaUploadModule(handle);

	return 0;
}

////////////////////////////////////////////////////////////////////////////////

MaUploadModule::MaUploadModule(void *handle):MaModule("upload", handle)
{
	uploadHandlerService = new MaUploadHandlerService();
}

////////////////////////////////////////////////////////////////////////////////

MaUploadModule::~MaUploadModule()
{
	delete uploadHandlerService;
}

////////////////////////////////////////////////////////////////////////////////
//////////////////////////// MaUploadHandlerService ////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MaUploadHandlerService::MaUploadHandlerService(): 
	MaHandlerService("uploadHandler")
{
#if BLD_FEATURE_LOG
	log = new MprLogModule("upload");
#endif
#if BLD_FEATURE_MULTITHREAD
	mutex = new MprMutex();
#endif
}

////////////////////////////////////////////////////////////////////////////////

MaUploadHandlerService::~MaUploadHandlerService()
{
#if BLD_FEATURE_LOG
	delete log;
#endif

#if BLD_FEATURE_MULTITHREAD
	delete mutex;
#endif
}

////////////////////////////////////////////////////////////////////////////////

MaHandler *MaUploadHandlerService::newHandler(MaServer * server, MaHost * host,
		char *ext)
{
	MaUploadHandler *ep;

	ep = new MaUploadHandler(ext, log);
	return ep;
}

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// MaUploadHandler ///////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MaUploadHandler::MaUploadHandler(char *ext, MprLogModule * serviceLog):
	MaHandler("uploadHandler", 0,
		MPR_HANDLER_POST | MPR_HANDLER_MAP_VIRTUAL |
		MPR_HANDLER_NEED_ENV | MPR_HANDLER_ALWAYS)
{
	log = serviceLog;

	contentState = MPR_UPLOAD_REQUEST_HEADER;
	boundary = 0;
	postBuf = new MprBuf();
	lenv	= new MprHashTable();
	upfile  = new MprFile();
	uploadDir = 0;
	filename = 0;
	filepath = 0;
}

////////////////////////////////////////////////////////////////////////////////

MaUploadHandler::~MaUploadHandler()
{
	if (boundary) {
		mprFree(boundary);
	}
	delete lenv;
	delete postBuf;
	delete upfile;
}

////////////////////////////////////////////////////////////////////////////////

MaHandler *MaUploadHandler::cloneHandler()
{
	MaUploadHandler	*ep;

	ep = new MaUploadHandler(extensions, log);
	ep->uploadDir = uploadDir;
	return ep;
}

////////////////////////////////////////////////////////////////////////////////

int MaUploadHandler::parseConfig(char *key, char *value, MaServer * server,
		MaHost * host, MaAuth * auth, MaDir * dir, MaLocation * location)
{
	char *path;

	if (mprStrCmpAnyCase(key, "FormUploadDir") == 0) {
		path = mprStrTrim(value, '\"');
		uploadDir = mprStrdup(path);
		mprLog(3, log, "Upload directory: %s\n", uploadDir);
		return 1;
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int MaUploadHandler::setup(MaRequest * rq)
{
	MaLimits *limits;

	limits = rq->host->getLimits();
	mprAssert(postBuf == 0);
	postBuf = new MprBuf(MPR_HTTP_IN_BUFSIZE, limits->maxBody);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	  Read some post data.
//
//	  Since the handler is non-terminal, this function never gets called
//	  by the server - we must pull the post data and call it manually!
//

void MaUploadHandler::postData(MaRequest * rq, char *buf, int len)
{
	char 	*key, *value, *name, *p, *line, *fileData, *filePath;
	int 	size, l, sigLen;

	fileData = 0;

	mprLog(5, log, "%d: postData %d bytes\n", rq->getFd(), len);
	if (len < 0 && rq->getRemainingContent() > 0) {
		return;
	}

	// copy the data to our buffer

	postBuf->copyDown();
	postBuf->put((uchar *) buf, len);
	postBuf->addNull();
	l = 0;

	while (1) {

		if (contentState == MPR_UPLOAD_CONTENT_END) {
			return;
		}

		if (contentState == MPR_UPLOAD_REQUEST_HEADER) {
			contentState = MPR_UPLOAD_CONTENT_HEADER;
			filename = 0;
		}

		if (contentState == MPR_UPLOAD_CONTENT_HEADER) {

			line = postBuf->getStart();
			p = strchr(line, '\n');
			if (!p) {
				// We've received only part of line
				return;
			}

			*(p++) = 0;
			postBuf->adjustStart(p - line);
			p = strchr(line, '\r');
			if (p) {
				*p = 0;
			}

			mprLog(3, log, "## %s\n", line);
			if (line[0] == 0) {
				// empty line means start of data
				contentState = MPR_UPLOAD_CONTENT_DATA;

				filename = getParameter("filename");
				if (filename) {
					filePath = makeFilePath(rq, filename);
					mprLog(3, log, "Receiving file: %s\n", filePath);
					upfile->open(filePath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
					mprFree(filePath);
				}

			} else {

				key = line;
				value = strchr(line, ':');
				if (value) {
					*(value++) = 0;
					// eat space after ':'
					while (*value == ' ') {
						value++;
					}
				}

				p = 0;
				if (value) {
					p = strchr(value, ';');
					if (p) {
						*(p++) = 0;
					}
					lenv->insert(new MprStringHashEntry(key, value));
				}
				// add command parameters to the handler environment

				if (p) {
					addParameters(p);
				}
			}
		}

		if (contentState == MPR_UPLOAD_CONTENT_DATA) {
			sigLen = strlen(boundary);
			size = postBuf->getLength();
			if (size < sigLen) {
				return;
			}

			p = findSig(postBuf->getStart(), size, boundary, sigLen);
			if (p) {
				// boundary signature found
				mprLog(3, log, "Boundary signature found, end of data.\n");
				fileData = postBuf->getStart();
				l = p - fileData;
				postBuf->adjustStart(l + sigLen);
				contentState = MPR_UPLOAD_CONTENT_DATA_END;

				name = getParameter("name");
				if (filename) {
					upfile->write(fileData, l);
					if (name) {
						rq->setVar(name, filename);
					}
				} else {
					// terminate form data with 0
					fileData[l] = 0;
					mprLog(3, log, "Setting variable: %s\n", name);
					rq->setVar(name, fileData);
				}

			} else {
				// no signature found
				if (postBuf->getLength() <= sigLen) {
					return;
				} else {
					fileData = postBuf->getStart();
					l = postBuf->getLength() - sigLen;
					if (filename) {
						upfile->write(fileData, l);
						postBuf->adjustStart(l);
					}
				}
			}
			if (contentState != MPR_UPLOAD_CONTENT_DATA) {
				if (filename) {
					upfile->close();
					filename = 0;
				}
			}
		}

		if (contentState == MPR_UPLOAD_CONTENT_DATA_END) {

			line = postBuf->getStart();
			p = (char *) memchr(line, '\n', postBuf->getLength());
			if (!p) {
				// Wait for end of line after boundary
				return;
			}
			*(p++) = 0;
			postBuf->adjustStart(p - line);
			p = strchr(line, '\r');

			// Strip CR
			if (p) {
				*p = 0;
			}
			lenv->removeAll();
			if (strcmp(line, "--") == 0) {
				mprLog(3, log, "End of content.\n");
				contentState = MPR_UPLOAD_CONTENT_END;
			} else {
				mprLog(3, log, "Starting new header...\n");
				contentState = MPR_UPLOAD_CONTENT_HEADER;
			}
		}
	}
	if (rq->getRemainingContent() <= 0) {
		contentState = MPR_UPLOAD_CONTENT_END;
	}
}

////////////////////////////////////////////////////////////////////////////////

int MaUploadHandler::run(MaRequest * rq)
{
	MaHeader *header;
	char *type, *param, *p;
	char *my_buf;
	int flags, l;

	flags = rq->getFlags();
	if (!(flags & MPR_HTTP_POST_REQUEST)) {
		return 0;
	}
	// Do we have any POST data ?
	if (rq->getRemainingContent() <= 0) {
		return 0;
	}

	header = rq->getHeader();
	type = mprStrdup(header->contentMimeType);
	p = strchr(type, '\r');
	if (p) {
		*(p++) = 0;
	}

	// Content type parameters are separated by ';'
	param = strchr(type, ';');
	if (param) {
		*(param++) = 0;
		addParameters(param, rq->getEnv());
	}
	// Set the upload directory variable
	rq->setVar("UPLOAD_DIR", uploadDir);

	// Make the multipart boundary signature
	p = rq->getVar("boundary", "");
	mprLog(4, log, "Multipart boundary: %s\n", p);
	boundary = (char *) mprMalloc(strlen(p) + 8);
	strcpy(boundary, "\r\n--");
	strcat(boundary, p);

	if (mprStrCmpAnyCase(type, "multipart/form-data") != 0) {
		mprLog(3, log, "Post data is not multipart\n");
		return 0;
	}

	// Process all the POST data
	rq->setPullPost();
	my_buf = (char *) mprMalloc(UPLOAD_BUF_SIZE);
	if (!my_buf) {
		return 0;
	}

	do {
		l = rq->readPostData(my_buf, UPLOAD_BUF_SIZE);
		postData(rq, my_buf, l);
	} while (l > 0);

	mprFree(my_buf);
	rq->setFlags(0, ~MPR_HTTP_PULL_POST);

	// Clear post flag to prevent EGI handler error:
	//  "Post data is not urlencoded"
	rq->setFlags(0, ~MPR_HTTP_POST_REQUEST);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	  Get local parameter
//

char *MaUploadHandler::getParameter(char *key)
{
	MprStringHashEntry 	*entry;
	char 				*value;

	entry = (MprStringHashEntry *) lenv->lookup(key);
	if (entry) {
		value = entry->getValue();
	} else {
		value = 0;
	}
	return value;
}

////////////////////////////////////////////////////////////////////////////////
//
//	  Add command parameters to the table.
//

int MaUploadHandler::addParameters(char *str, MprHashTable * tab)
{
	char 		*name, *value, *p;
	int 		n;

	n = 0;

	if (!str) {
		return n;
	}
	if (!tab) {
		tab = lenv;
	}
	p = str;
	while (p) {
		while (*p == ' ') {
			p++;
		}
		name = p;
		value = strchr(p, '=');
		if (value) {
			*(value++) = 0;
			if (*value == '"') {
				*(value++) = 0;
				p = strchr(value, '"');
				if (p) {
					*(p++) = 0;
				} else {
					break;
				}
			}
		} else {
			value = "";
		}
		p = strchr(p, ';');
		if (p) {
			*(p++) = 0;
		}
		tab->insert(new MprStringHashEntry(name, value));
	}
	return n;
}

////////////////////////////////////////////////////////////////////////////////
//
//	  Make full incoming file path from filename.
//	  Must be released by mprFree().

char *MaUploadHandler::makeFilePath(MaRequest * rq, char *name)
{
	char *docRoot, *fullPath, *p;
	int length;

	// Strip some characters for security reasons

	while (1) {
		p = strpbrk(name, "/\\:");
		if (!p)
			break;
		name = p;
	}
#if 0
	docRoot = rq->getVar("DOCUMENT_ROOT", ".");
#else
   // We don't want the upload directory to be relative to the DocumentRoot
   docRoot = ".";
#endif
	length = strlen(docRoot) + strlen(uploadDir) + strlen(name) + 8;
	fullPath = (char *) mprMalloc(length);
	if (fullPath) {
		strcpy(fullPath, docRoot);
		strcat(fullPath, "/");
		strcat(fullPath, uploadDir);
		strcat(fullPath, "/");
		strcat(fullPath, name);
	}
	return fullPath;
}

////////////////////////////////////////////////////////////////////////////////
//
//	  Find a signature in memory
//	  Returns pointer to the first match
//

static char *findSig(void *buf, int buf_length, void *sig, int sigLen)
{
	char 	*p, *p_end;
	char 	first;

	first = *((char *) sig);
	p = (char*) buf;

	if (buf_length < sigLen) {
		return 0;
	}
	p_end = p + (buf_length - sigLen) + 1;
	while (p < p_end) {
		p = (char *) memchr(p, first, p_end - p);
		if (!p) {
			return 0;
		}
		if (memcmp(p, sig, sigLen) == 0) {
			return p;
		}
		p++;
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
#else

void mprUploadHandlerDummy()
{
}

#endif // BLD_FEATURE_UPLOAD_MODULE

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
