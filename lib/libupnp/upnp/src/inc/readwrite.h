///////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2000-2003 Intel Corporation 
// All rights reserved. 
//
// Redistribution and use in source and binary forms, with or without 
// modification, are permitted provided that the following conditions are met: 
//
// * Redistributions of source code must retain the above copyright notice, 
// this list of conditions and the following disclaimer. 
// * Redistributions in binary form must reproduce the above copyright notice, 
// this list of conditions and the following disclaimer in the documentation 
// and/or other materials provided with the distribution. 
// * Neither name of Intel Corporation nor the names of its contributors 
// may be used to endorse or promote products derived from this software 
// without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL INTEL OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY 
// OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
///////////////////////////////////////////////////////////////////////////

#ifndef GENLIB_NET_HTTP_READWRITE_H
#define GENLIB_NET_HTTP_READWRITE_H

#include <genlib/net/http/parseutil.h>

#define DEF_TIMEOUT     30

// read http message from the given TCP connection
// return codes:
//   0: success
//  -1: std error; check errno
//  HTTP_E_BAD_MSG_FORMAT
//  HTTP_E_OUT_OF_MEMORY
//  HTTP_E_TIMEDOUT
int http_RecvMessage( IN int tcpsockfd, OUT HttpMessage& message,
    UpnpMethodType requestMethod = HTTP_UNKNOWN_METHOD,
    int timeoutSecs = DEF_TIMEOUT );

// write the http message to the TCP connection
// return codes:
//   0: success
//  -1: std error; check errno
//  HTTP_E_OUT_OF_MEMORY
//  HTTP_E_TIMEDOUT
int http_SendMessage( IN int tcpsockfd, IN HttpMessage& message,
    int timeoutSecs = DEF_TIMEOUT );

// return codes:
//   0: success
//  -1: std error; check errno
//  HTTP_E_BAD_MSG_FORMAT
//  HTTP_E_OUT_OF_MEMORY
//  HTTP_E_TIMEDOUT
int http_Download( IN const char* resourceURL,  OUT HttpMessage& resource,
    int timeoutSecs = DEF_TIMEOUT);

// return codes:
//   > 0 : connection fd
//  -1: std error; check errno
//  HTTP_E_TIMEDOUT
int http_Connect( const char* resourceURL );

#endif /* GENLIB_NET_HTTP_READWRITE_H */

