# -*- Fundamental -*-
# http_keepalive.inc
#
# (C) Tenable Network Security
#
# $Id: http_keepalive.inc,v 1.78 2006/09/08 17:15:19 theall Exp $
#
#
# The only function which should be used by an external plugin is
# http_keepalive_send_recv(port, data) which returns the result
# (or NULL if no connection could be established).
#
# Note that the file "http_func.inc" must also be included when
# using this file.
#

global_var __ka_socket, __ka_port, __ka_enabled, __ka_last_request;

__ka_socket = 0;
__ka_port   = 0;
__ka_enabled = -1;
__ka_last_request = "";


#if (isnull(debug_level)) include("global_settings.inc");

#
# Based on the last headers we received, we determine if we need
# to close our socket and re-open it or not
#
function http_keepalive_check_connection(headers)
{
 local_var tmp;
 tmp = egrep(pattern:"^Connection: [Cc]lose", string:headers);
 if(tmp)
 {
     if ( __ka_socket ) http_close_socket(__ka_socket);
     __ka_socket = http_open_socket(__ka_port);
 }
}

function enable_keepalive(port)
{
 __ka_enabled = 1;
 __ka_port    = port;
 __ka_socket  = http_open_socket(port);
}
#
# This function determines if the remote web server is
# keep-alive-enabled or not.
#
function http_keepalive_enabled(port)
{
  local_var req, soc, r, kb;
  
  kb = get_kb_item(strcat("www/", port, "/keepalive"));

  if(kb == "yes"){
  	enable_keepalive(port:port);
	return(1);
	}
  else if(kb == "no")return(0);

  req = strcat('GET / HTTP/1.1\r\n',
'Connection: Keep-Alive\r\n',
'Host: ', get_host_name(), '\r\n',
'Pragma: no-cache\r\n',
'User-Agent: Mozilla/4.75 [en] (X11, U; Nessus)\r\n\r\n');

  soc = http_open_socket(port);
  if(!soc)return -2;
  send(socket:soc, data:req);
  r = http_recv(socket:soc);


  # Apache
  if(egrep(pattern:"^Keep-Alive:.*", string:r))
  	{
	http_close_socket(soc);
	set_kb_item(name:strcat('www/', port, '/keepalive'), value:"yes");
	enable_keepalive(port:port);
    	return(1);
	}
  else
  	{
	# IIS
	send(socket:soc, data:req);
	r = http_recv(socket:soc);
	http_close_socket(soc);
	if(strlen(r)){
		set_kb_item(name:strcat("www/", port, "/keepalive"), value:"yes");
		enable_keepalive(port:port);
		return(1);
		}
	}

 set_kb_item(name:strcat("www/", port, "/keepalive"), value:"no");
 return(0);
}


#
# This function is akin to http_recv_body() except that if the last request
# was a HEAD, we bail out (whereas http_recv() will timeout).
#
function http_keepalive_recv_body(headers, bodyonly)
{
  local_var body, length, tmp, chunked, killme;

  killme = 0;
  length = -1;

  if(ereg(pattern:"^HEAD.*HTTP/.*", string:__ka_last_request))
   {
   # HEAD does not return a body
   http_keepalive_check_connection(headers:headers);
   if(bodyonly) return("");
   else return(headers);
   }


  if("Content-Length" >< headers || "Content-length" >< headers )
  {
    tmp = egrep(string:headers, pattern:"^Content-[Ll]ength: *[0-9]+");
    if ( tmp ) length = int(ereg_replace(string:tmp, pattern:"^Content-[Ll]ength: *([0-9]*) *", replace:"\1"));
  }



 if((length < 0) && (egrep(pattern:"transfer-encoding: chunked", string:headers, icase:TRUE)))
 {
   while(1)
   {
   tmp = recv_line(socket:__ka_socket, length:4096);
   length = hex2dec(xvalue:tmp);
   if(length > 1048576)
   	{
   	length = 1048576;
	killme = 1;
	}
   body  = strcat(body, recv(socket:__ka_socket, length:length, min:length));
   # "\r\n"
   recv (socket:__ka_socket, length:2, min:2);
   if (strlen(body) > 1048576) killme = 1;

   if(length == 0 || killme){
   	http_keepalive_check_connection(headers:headers);
    # This is expected - don't put this line before the previous
   	if(bodyonly) return(body);
    else return(strcat(headers, '\r\n', body));
	}
   }
 }


 if(length >= 0)
 {
   # Don't receive more than 1 MB
   if (length > 1048576) length = 1048576;

   body = recv(socket:__ka_socket, length:length, min:length);
 }
 else {
 	# If we don't have the length, we close the connection to make sure
	# the next request won't mix up the replies.

 	#display("ERROR - Keep Alive, but no length!!!\n", __ka_last_request);
	body = recv(socket:__ka_socket, length:16384, min:0);
        if (body =~ '<html>' && body !~ '</html>')	# case insensitive
        {
         repeat
         {
          tmp = recv(socket:__ka_socket, length:16384);
          body += tmp;
         }
         until (! tmp || body =~ "</html>");
         if (debug_level && body !~ "</html>") display("http_keepalive_recv_body: incomplete body?\n------------\n", body, "\n------------\n");
        }
	http_close_socket(__ka_socket);
	__ka_socket = http_open_socket(__ka_port);
	}


 http_keepalive_check_connection(headers:headers);
 if(bodyonly) return(body);
 else return(strcat(headers, '\r\n', body));
}


#----------------------------------------------------------------------#

# We close our socket on exit.
function on_exit()
{
  if(__ka_socket)
  {
    http_close_socket(__ka_socket);
    __ka_socket = 0;
  }
}


if ( 0 ) on_exit();


#----------------------------------------------------------------------#


#
# This is our "public" Keep-Alive function. It sends <data> to the remote
# host on port <port>, and returns the result, or NULL if no connection
# could be established.
#
function http_keepalive_send_recv(port, data, bodyonly, embedded, fetch404)
{
  local_var id, n, ret, headers;
  local_var soc, r, body;

  
  if ( ! embedded && get_kb_item("Services/www/" + port + "/embedded") ) return NULL;

  if (debug_level > 1) 
   display("http_keepalive_send_recv(port: ", port, ", data: ", data, ", bodyonly: ", bodyonly, ")\n");

  if ( ! data ) { display("http_keepalive_send_recv(): NULL data!\n"); return NULL; }

  if(__ka_enabled == -1) __ka_enabled = http_keepalive_enabled(port:port);
  if(__ka_enabled == -2) return NULL;


  if(__ka_enabled == 0)
  {
    soc = http_open_socket(port);
    if(!soc)return NULL;
    if (send(socket:soc, data:data) <= 0)
    {
      http_close_socket(soc);
      return NULL;
    }
    headers = http_recv_headers2(socket:soc);
    # If the headers are not HTTP compliant, just return right away
    if ( headers && !ereg(pattern:"^HTTP/.* [0-9]+", string:headers) )
       return headers;
 
    if(headers && ( !ereg(pattern:"^HTTP/.* 404", string:headers) || fetch404 == TRUE ) ) 
    	body = http_recv_body(socket:soc, headers:headers, length:0);

    http_close_socket(soc);
    if(bodyonly) return(body);
    else return(strcat(headers, '\r\n', body));
  }


  if((port != __ka_port)||(!__ka_socket))
  {
    if(__ka_socket)http_close_socket(__ka_socket);
    __ka_port = port;
    __ka_socket = http_open_socket(port);
    if(!__ka_socket)return NULL;
  }

  id = stridx(data, '\r\n\r\n');
  data = str_replace(string:data, find:"Connection: Close", replace:"Connection: Keep-Alive", count:1);
  __ka_last_request = data;
  n = send(socket:__ka_socket, data:data);
  if (n >= strlen(data))
    headers = http_recv_headers2(socket:__ka_socket);
  if (! headers)
  {
    http_close_socket(__ka_socket);
    __ka_socket = http_open_socket(__ka_port);
    if(__ka_socket == 0)return NULL;
    if (send(socket:__ka_socket, data:data) < strlen(data))
    {
      http_close_socket(__ka_socket);
      __ka_socket = NULL;
      return NULL;
    }
    headers = http_recv_headers2(socket:__ka_socket);
  }

  return  http_keepalive_recv_body(headers: headers, bodyonly:bodyonly);
}



#
# Same as check_win_dir_trav(), but with KA support
#
function check_win_dir_trav_ka(port, url)
{
  local_var	soc, req, cod, buf;

  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req);

  if ( "; for 16-bit app support" >< buf )
  {
    return(1);
  }
  return(0);
}

#
#
#
function is_cgi_installed_ka(item, port, embedded)
{
 local_var r, no404, dir, slash, dirs, banner;

 if ( ! embedded && get_kb_item("Services/www/" + port + "/embedded") ) return 0;
 if ( get_kb_item("Settings/disable_cgi_scanning") )  return 0;

 banner = get_http_banner(port:port);

 if(item[0] != "/")
 {
  dirs = cgi_dirs();
  slash = "/";
 }
 else
 {
  dirs = make_list("");
  slash = "";
 }
 
 no404 = get_kb_item(strcat("www/no404/", port));
 if ( strlen(no404) >= 1 ) return NULL;

 foreach dir (dirs)
 {
 r = http_keepalive_send_recv(port:port, data:http_get(item:dir + slash + item, port:port));
 if( r == NULL ) return NULL;

 if(r =~ "^HTTP/1\.[0-9.] +200 +")
  {
  if(no404 && tolower(no404) >< tolower(r)) return 0;
  else return(1);
  }
 }
 return(0);
}

#
  
function get_http_page(port, url, redirect)
{
  local_var	r, u, v, i, l, seen_loc, n;

  if (isnull(redirect))
    n = 32;
  else if (redirect <= 0)
    n = 1;
  else
    n = redirect + 1;

  seen_loc = make_list();
  u = url;
  for (i = 0; i < n; i ++)	# Limited iterations to avoid traps
  {
    seen_loc[u] = 1;
    r = http_keepalive_send_recv(port: port, 
				data: http_get(port: port, item: u));
    if (isnull(r)) return NULL;

    if (r =~ "^HTTP/1\.[01] +30[0-9] .*")
    {
      v = eregmatch(pattern: '\r\nLocation: *([^ \t\r\n]+)[ \t]*[\r\n]+',
		string: r, icase: 1);
      if (isnull(v)) return NULL;	# Big problem
      l = v[1];
      if (seen_loc[l]) return NULL;
      seen_loc[l] = 1;
    }
    else if (r =~ "^HTTP/1\.[01] +200 ")
    {
      r = strstr(r, '\r\n\r\n');
      r = substr(r, 4);
      return r;
    }
    else	# Code 4xx or 5xx
      return NULL;
  }
  # Loop?
  return NULL;
}



function http_get_cache(port, item)
{
 local_var req, res;

 res = get_kb_item("Cache/" + port + "/URL_" + item );
 if ( res ) return res;

 req = http_get(port:port, item:item);
 res = http_keepalive_send_recv(port:port, data:req, embedded:TRUE);
 if ( ! res ) return NULL;

 if ( defined_func("replace_kb_item") )
	replace_kb_item(name:"Cache/" + port + "/URL_" + item, value:res);
 else
	set_kb_item(name:"Cache/" + port + "/URL_" + item, value:res);

 return res;
}



function http_check_remote_code (default_port, extra_dirs, unique_dir, check_request, extra_check, check_result, command, description, port, embedded)
{
 local_var list, req, txt_result, txt_desc, extra, dir, buf;
 if ( get_kb_item("Settings/disable_cgi_scanning") )  exit(0);

 if (unique_dir)
   list = make_list (unique_dir);
 else
 {
  if (!isnull(extra_dirs))
    list = make_list (cgi_dirs(), extra_dirs);
  else
    list = make_list (cgi_dirs());
 }

 if ( ! port )
 {
 if (default_port)
   port = get_http_port(default:default_port);
 else
   port = get_http_port(default:80); 
 }

 if ( ! embedded && get_kb_item("Services/www/" + port + "/embedded") ) exit(0);
 if (!get_port_state(port))
   exit (0);


 foreach dir (list)
 {
   req = string(dir, check_request);
   req = http_get(item:req, port:port);
   buf = http_keepalive_send_recv(port:port, data:req);
   if (buf == NULL)
     exit(0);

   txt_result = egrep(pattern:check_result, string:buf);
   if (extra_check)
   {
    extra = 0;
    if (egrep (pattern:extra_check, string:buf))
      extra = 1;
   }
   else
     extra = 1;

   if (txt_result && extra)
   {
    txt_desc = description + 
"

Plugin output :

It was possible to execute the command '" + command + "' on the remote host,
which produces the following output :

"
    + txt_result;

    security_hole (port:port, data:txt_desc);
    exit (0);
   }
 }
}
