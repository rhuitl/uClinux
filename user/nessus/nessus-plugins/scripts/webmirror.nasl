#
# WEBMIRROR 2.0
#
#
# Written by Renaud Deraison <deraison@nessus.org>
# includes some code by H D Moore <hdmoore@digitaldefense.net>
#
# This plugin mirrors the paths used by a website. We typically care
# to obtain the list of CGIs installed on the remote host, as well as
# the path they are installed under. 
#
# Note that this plugin does not properly check for the syntax of the
# HTML pages returned : it tries to extract as much info as it
# can. We don't care about the pages extensions either (but we do
# case about the mime types)
#
# This plugin takes a really long time to complete, so it updates
# the KB as soon as data is found (as it's likely to be killed
# by nessusd against huge sites)
#
# Features :
#
#  o Directories are added in additions to URIs (ie: if there is a link to /foo/bar/a.gif, then webmirror
#    will crawl /foo/bar/)
#  o Apache and iPlanet directory listing features are used (/foo/bar will be requested as /foo/bar?D=A and
#    /foo/bar/?PageServices)   [thanks to MaXX and/or Nicolas Fischbach for the suggestion]
#  o Content is stored by various keys in the kb, to be easily reused by other scripts
#  o Forms and URIs ending in '?.*' are recognized and a list of CGIs is made from them
#  o Keep-alive support
#
# See also :
#  o torturecgis.nasl
#  o bakfiles.nasl
#  o officefiles.nasl
#
# This is version 2.0 of the plugin - it should be WAY faster and more
# accurate (i wrote a real parser).
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10662);
 # script_cve_id("CVE-MAP-NOMATCH");
 script_version("$Revision: 1.104 $");
 
 name["english"] = "Web mirroring";
 script_name(english:name["english"]);
 
 desc["english"] = "
This script makes a mirror of the remote web site(s)
and extracts the list of CGIs that are used by the remote
host.

It is suggested you give a high timeout value to
this plugin and that you change the number of
pages to mirror in the 'Options' section of
the client.

Risk factor : None";

 script_description(english:desc["english"]);
 
 summary["english"] = "Performs a quick web mirror";
 script_summary(english:summary["english"]); 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 - 2003 Renaud Deraison");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "httpver.nasl", "DDI_Directory_Scanner.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 # There was a memory leak that made webmirror eat much memory
 # It is now fixed but there was no NASL_LEVEL defined for it. However,
 # we know that NASL_LEVEL was increased to 2181 _after_ the fix
 # Better than nothing...
 if (NASL_LEVEL >= 2181)
 script_add_preference(name:"Number of pages to mirror : ",
 			type:"entry",
			value:"200");
 else
 script_add_preference(name:"Number of pages to mirror : ",
 			type:"entry",
			value:"20");
 script_add_preference(name:"Start page : ",
 			type:"entry",
			value:"/");			
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

#------------------------------------------------------------------------#

global_var start_page, max_pages, dirs, num_cgi_dirs, max_cgi_dirs;
global_var debug, port, URLs, URLs_hash, ID_WebServer, Apache, iPlanet;
global_var CGIs, Misc, Dirs, CGI_Dirs_List, URLs_30x_hash, URLs_auth_hash, Code404;
global_var misc_report, cnt, RootPasswordProtected, coffeecup, guardian;
global_var URL, page, report, foo;

#-------------------------------------------------------------------------#


function my_http_recv(socket)
{
  local_var	h, b, l;
 
  h = http_recv_headers2(socket:socket);
  if(!h)return(NULL);
  
  if("Content-Type" >< h && !egrep(pattern:"^Content-Type: text/(xml|html)", string:h))return(h);
  
  
  b = http_recv_body(socket: socket, headers: h, length:0);
  return (string(h, "\r\n", b));
}



function my_http_keepalive_recv()
{
  local_var headers, body, length, tmp, chunked, killme;

  killme = 0;
  length = -1;
  headers = http_recv_headers2(socket:__ka_socket);
  if(strlen(headers) == 0)headers = http_recv_headers2(socket:__ka_socket);
  
  if(substr(__ka_last_request, 0, 3) == "HEAD"  )
   {
   # HEAD does not return a body
   return(headers);
   }
  
  if("Content-Type" >< headers)
  {
   if(!egrep(pattern:"^Content-Type: text/(xml|html)", string:headers))
   	{
	 http_close_socket(__ka_socket);
	 __ka_socket = 0;
	 return(headers);
	}
  }
  
  if("Content-Length" >< headers)
  {
    tmp = egrep(string:headers, pattern:"^Content-Length: [0-9]*");
    length = int(ereg_replace(string:tmp, pattern:"^Content-Length: ([0-9]*)", replace:"\1"));
  }
  
 

 if((length < 0) && (egrep(pattern:"^transfer-encoding: chunked", string:headers, icase:TRUE)))
 {
   while(1)
   {
   tmp = recv_line(socket:__ka_socket, length:4096);
   length = hex2dec(xvalue:tmp);
   if(length > 512*1024)
   	{
   	length = 512*1024;
	killme = 1;
	}
   body  = string(body, recv(socket:__ka_socket, length:length+2, min:length+2));
   if(strlen(body) > 512*1024)killme = 1;
   
   if(length == 0 || killme){
   	http_keepalive_check_connection(headers:headers);
   	return(string(headers,"\r\n", body)); # This is expected - don't put this line before the previous
	}
   }
 }
 

 if(length >= 0)
 {
   if(length > 512*1024)length = 512*1024;
   
   body = recv(socket:__ka_socket, length:length, min:length);
 }
 else {
 	# If we don't have the length, we close the connection to make sure
	# the next request won't mix up the replies.
	
 	#display("ERROR - Keep Alive, but no length!!!\n", __ka_last_request);
	body = recv(socket:__ka_socket, length:16384);
	http_close_socket(__ka_socket);
	__ka_socket =  http_open_socket(__ka_port);
	}

 

 http_keepalive_check_connection(headers:headers);
 return(string(headers,"\r\n", body));
}



function my_http_keepalive_send_recv(port, data)
{
  local_var id, n;
  
  if(data == NULL)
   return;

  if(__ka_enabled == -1)__ka_enabled = http_keepalive_enabled(port:port);



  if(__ka_enabled == 0)
  {
    local_var soc, r;
    soc = http_open_socket(port);
    if(!soc)return NULL;
    send(socket:soc, data:data);
    r = my_http_recv(socket:soc);
    http_close_socket(soc);
    return r;
  }


  if((port != __ka_port)||(!__ka_socket))
  {
    if(__ka_socket)http_close_socket(__ka_socket);
    __ka_port = port;
    __ka_socket =  http_open_socket(port);
    if(!__ka_socket)return NULL;
  }

  id = stridx(data, string("\r\n\r\n"));
  data = str_replace(string:data, find:"Connection: Close", replace:"Connection: Keep-Alive", count:1);
  __ka_last_request = data;
  n = send(socket:__ka_socket, data:data);
  if(n <= 0)
  {
    http_close_socket(__ka_socket);
    __ka_socket = http_open_socket(__ka_port);
    if(__ka_socket == 0)return NULL;
    send(socket:__ka_socket, data:data);
  }

  return(my_http_keepalive_recv());
}

#-------------------------------------------------------------------#


function add_cgi_dir(dir)
{
 local_var d, dirs, req, res;

 if ( num_cgi_dirs >= max_cgi_dirs ) return 0;
 
 req = http_get(item:string(dir, "/non-existant-", rand()), port:port);
 req = my_http_keepalive_send_recv(port:port, data:req);
 if(ereg(pattern:"^HTTP/.\.. 404 ", string:req))
 {
  dirs = cgi_dirs();
  foreach d (dirs)
  {
  if(d == dir)return(0);
  }
 
  if(isnull(CGI_Dirs_List[dir]))
  {
   if ( debug >= 1 ) display("Adding ", dir, " as a CGI directory (num#", num_cgi_dirs, "/", max_cgi_dirs, ")\n");
   set_kb_item(name:"/tmp/cgibin", value:dir);
   CGI_Dirs_List[dir] = 1;
   num_cgi_dirs ++;
  }
 }
}


#--------------------------------------------------------------------------#

function add_30x(url)
{
 if(isnull(URLs_30x_hash[url]))
 {
  set_kb_item(name:string("www/", port, "/content/30x"), value:url);
  URLs_30x_hash[url] = 1;
 }
}


function add_auth(url)
{
 if(isnull(URLs_auth_hash[url]))
 {
  set_kb_item(name:string("www/", port, "/content/auth_required"), value:url);
  URLs_auth_hash[url] = 1;
  if(url == "/")RootPasswordProtected = 1;
 }
}

#--------------------------------------------------------------------------#

num_url = 0;

function add_url(url)
{
 local_var ext, dir;
  
 if ( num_url > 100 ) return 0;
 
 if(debug > 5)display("**** ADD URL ", url, "\n");
 if(isnull(URLs_hash[url]))
 {
  URLs = make_list(URLs, url);
  URLs_hash[url] = 0;
   
  url = ereg_replace(string:url,
  			pattern:"(.*)\?.*",
			replace:"\1");
			
			
  ext = ereg_replace(pattern:".*\.([^\.]*)$", string:url, replace:"\1");
  if(strlen(ext) && ext[0] != "/" && strlen(ext) < 5 )
  {
   set_kb_item(name:string("www/", port, "/content/extensions/", ext), value:url);
  }
  
  dir = dir(url:url);
  if(dir && !Dirs[dir])
  {
   Dirs[dir] = 1;
   set_kb_item(name:string("www/", port, "/content/directories"), value:dir);
   if(isnull(URLs_hash[dir]))
   {
    URLs = make_list(URLs, dir);
    if(Apache)URLs  = make_list(URLs,  string(dir, "/?D=A"));
    else if(iPlanet)URLs = make_list(URLs,  string(dir, "/?PageServices"));
    URLs_hash[dir] =  0;
   }
  }
 }
}

function cgi2hash(cgi)
{
 local_var cur_cgi, cur_arg, i, ret;
 
 ret = make_list();
 
 for(i=0;i<strlen(cgi);i++)
 {
  if(cgi[i] == " " && cgi[i+1] == "[")
  {
    cur_arg = "";
    for(i=i+2;i<strlen(cgi);i++)
    {
      if(cgi[i] == "]")
      {
        ret[cur_cgi] = cur_arg;
	cur_cgi = "";
	cur_arg = "";
	if(i + 2 >= strlen(cgi))return ret;
	i += 2;
	break;
      }
      else cur_arg += cgi[i];
    }
  }
  cur_cgi += cgi[i];
 } 
 return ret;
}

function hash2cgi(hash)
{
 local_var ret, h;
 
 ret = "";
 foreach h (keys(hash))
 {
  ret += string(h, " [", hash[h], "] ");
 }
 return ret;
}


function add_cgi(cgi, args)
{
 local_var mydir, tmp, a, new_args, common, c;
 
 args = string(args);

 if(isnull(CGIs[cgi]))
 {
  CGIs[cgi] = args;
  mydir = dir(url:cgi);
  add_cgi_dir(dir:mydir);
 }
 else {
    tmp = cgi2hash(cgi:CGIs[cgi]);
    new_args = cgi2hash(cgi:args);
    common = make_list();
    foreach c (keys(tmp))
    {
     common[c] = tmp[c];
    }
    
    foreach c (keys(new_args))
    {
     if(isnull(common[c]))common[c] = new_args[c];
    }
    CGIs[cgi] = hash2cgi(hash:common);
    }
}



#---------------------------------------------------------------------------#

function dir(url)
{
 return ereg_replace(pattern:"(.*)/[^/]*", string:url, replace:"\1");
}

function remove_cgi_arguments(url)
{
 local_var idx, cgi, cgi_args, args, arg, a, b;
 
 # Remove the trailing blanks
 while(url[strlen(url) - 1] == " ")
 {
  url = substr(url, 0, strlen(url) - 2);
 }
 
 idx = stridx(url, "?");
 if(idx < 0)
  return url;
 else if(idx >= strlen(url) - 1)
 {
  cgi = substr(url, 0, strlen(url) - 2);
  add_cgi(cgi:cgi, args:"");
  return cgi;
 }
 else
 {
  if(idx > 1)cgi = substr(url, 0, idx - 1);
  else cgi = ".";
  
  #
  # Avoid Apache's directories indexes
  #
  if ( strlen(cgi) > 0 && cgi[strlen(cgi) - 1] == "/" && 
	ereg(pattern:"[DMNS]=[AD]", string:substr(url, idx + 1, strlen(url) - 1))) return NULL;
  cgi_args = split(substr(url, idx + 1, strlen(url) - 1), sep:"&");
  foreach arg (make_list(cgi_args)) 
  {
   arg = arg - "&";
   arg = arg - "amp;";
   a = ereg_replace(string:arg, pattern:"(.*)=.*", replace:"\1");
   b = ereg_replace(string:arg, pattern:".*=(.*)", replace:"\1");
   if(a != b)
  	 args = string(args, a , " [", b, "] ");
   else
   	 args = string(args, arg, " [] ");
  }
  add_cgi(cgi:cgi, args:args);
  return cgi;
 }
}


function basename(name, level)
{
 local_var i;
 
 if(strlen(name) == 0)
  return NULL;
  

  for(i = strlen(name) - 1; i >= 0 ; i --)
  {
   if(name[i] == "/")
   {
    level --;
    if(level < 0)
    { 
     return(substr(name, 0, i));
    }
   }
 }
 
 # Level is too high, we return /
 return "/";
}



function canonical_url(url, current)
{
 local_var num_dots, i, location ;
 

 
 if(debug > 1)display("***** canonical '", url, "' (current:", current, ")\n");
 
 if(strlen(url) == 0)
  return NULL;
  
 if(url[0] == "#")
  return NULL;
 
 
 if(url == "./" || url == ".")
   return current;
  
 
 if(debug > 2)display("**** canonical(again) ", url, "\n");
 
 if(ereg(pattern:"[a-z]*:", string:url, icase:TRUE))
 {
  if(ereg(pattern:"^http://", string:url, icase:TRUE))
  {
   location = ereg_replace(string:url, pattern:"http://([^/]*)/.*", replace:"\1", icase:TRUE);
   if(location != url)
   {
    if(location != get_host_name())return NULL;
    else return remove_cgi_arguments(url:ereg_replace(string:url, pattern:"http://[^/]*/([^?]*)", replace:"/\1", icase:TRUE));
   }
  }
 }
 else
 {
 if(url == "//")  return "/";

 if(ereg(pattern:"^//.*", string:url, icase:TRUE))
 {
  location = ereg_replace(string:url, pattern:"//([^/]*)/.*", replace:"\1", icase:TRUE);
  if(location != url)
  {
   if(location == get_host_name())return remove_cgi_arguments(url:ereg_replace(string:url, pattern:"//[^/]*/([^?]*)", replace:"/\1", icase:TRUE));
  }
  return NULL;
 }
 
 if(url[0] == "/")
  return remove_cgi_arguments(url:url);
 else
 {
  i = 0;
  num_dots = 0;
 
  while ( url[0] == " ") url = url - " ";
  while(i < strlen(url) - 2 && url[i] == "." && url[i+1] == "." && url[i+2] == "/")
  {
   num_dots ++;
   url = url - "../";
   if(strlen(url) == 0)break;
  }
  
  while(i < strlen(url) && url[i] == "." && url[i+1] == "/")
  {
    url = url - "./";
    if(strlen(url) == 0)break;
  }
  url = string(basename(name:current, level:num_dots), url);
 }
 
 i = stridx(url, "#");
 if(i >= 0)url = substr(url, 0, i - 1);
 

 if(url[0] != "/")
 	return remove_cgi_arguments(url:string("/", url));
 else
 	return remove_cgi_arguments(url:url);
 }
 return NULL;
}



#--------------------------------------------------------------------#

 
function my_http_get(item, port)
{
 local_var ret, accept, idx;
 
 ret = http_get(item:item, port:port);
 accept = egrep(string:ret, pattern:"^Accept:");
 ret = ret - accept;
 idx = stridx(ret, string("\r\n\r\n"));

 
 ret = insstr(ret, string("\r\nAccept: text/html, text/xml\r\n\r\n"), idx);
 return ret;
}


function extract_location(data)
{
 local_var loc, url;
 

 
 loc = egrep(string:data, pattern:"^Location: ");
 if(!loc) return NULL;
 
 loc = loc - string("\r\n");
 loc = ereg_replace(string:loc, 
                              pattern:"^Location: (.*)$",
                              replace:"\1");
 
 
 
  url = canonical_url(url:loc, current:"/"); 
  if( url )
  {
   add_url(url : url);
   return url;
  }
  
  return NULL;
}



function retr( port, page )
{
 local_var req, resp, q, code, harray;
 
 if( debug )display("*** RETR ", page, "\n");
  
 req = my_http_get(item:page, port:port);
 resp = my_http_keepalive_send_recv(port:port, data:req);
 harray = headers_split(h:resp);
 if( resp == NULL ) exit(0); # No web server
 if ( strlen(resp) < 12 ) return NULL;
 code = int(substr(resp, 9, 11));
 
 if(code != 200 )
 {
  if(code == 401 || code == 403 )
     {
      add_auth(url:page);
      return NULL;
     }
  if(code == 301 || code == 302 )
  { 
   q = harray["location"];
   add_30x(url:page);
   
   # Don't echo back what we added ourselves...
   if(!(("?PageServices" >< page || "?D=A" >< page) && ("?PageServices" >< q || "?D=A" >< q)))
   	extract_location(data:resp);
   return NULL;
  }
 }
 
 if ( ! ID_WebServer )
 {
 if ( "Apache" >< harray["server"] ) Apache ++;
 else if ( "Netscape" >< harray["server"] ) iPlanet ++;
 ID_WebServer ++;
 }
 
 
 if(harray["content-type"] && !ereg(pattern:"text/(xml|html)", string:harray["content-type"]))
 	return NULL;
 else 
 	{
	resp = strstr(resp, string("\r\n\r\n"));
	if(!resp)return NULL; # Broken web server ?
	resp = str_replace(string:resp, find:string("\r\n"), replace:" ");
	resp = str_replace(string:resp, find:string("\n"), replace:" ");
	resp = str_replace(string:resp, find:string("\t"), replace:" ");
 	return resp;
	}
}

#---------------------------------------------------------------------------#


function token_split(content)
{
 local_var i, j, k, str;
 local_var ret, len, num;
 
 num = 0;
 
 ret = make_list();
 len = strlen(content);
 
 for (i=0;i<len;i++)
 {
  if(((i + 3) < len) && content[i]=="<" && content[i+1]=="!" && content[i+2]=="-" && content[i+3]=="-")
  {
   j = stridx(content, "-->", i);
   if( j < 0)return(ret);
   i = j;
  }
 else  
  if(content[i]=="<")
  {
   str = "";
   i ++;
   
   while(i < len && content[i] == " ")i ++;
   
   for(j = i; j < len ; j++)
   {
    if(content[j] == '"')
    {
      k = stridx(content, '"', j + 1);
      if(k < 0){
      	return(ret); # bad page
	}
      str = str + substr(content, j, k);
      j = k;
    }
    else if(content[j] == '>')
    {        
     if(ereg(pattern:"^(a|area|frame|meta|iframe|link|img|form|/form|input|button|textarea|select|applet)( .*|$)", string:str, icase:TRUE))
     	{
        num ++;
     	ret = make_list(ret, str);
        if ( num > 50 ) return ret; # Too many items
	}
     break;
    }
    else str = str + content[j];
   }
   i = j;
  }
 }
 
 return(ret);
}



function token_parse(token)
{
 local_var ret, i, j, len, current_word, word_index, current_value, char;
 
 
 ret = make_array();
 len = strlen(token);
 current_word = "";
 word_index = 0;
 
 for( i = 0 ; i < len ; i ++)
 {
  if((token[i] == " ")||(token[i] == "="))
  {
   while(i+1 < len && token[i+1] == " ")i ++;
   if(i >= len)break;
   
   if(word_index == 0)
   {
    ret["nasl_token_type"] = tolower(current_word);
   }
   else
   {
    while(i+1 < len && token[i] == " ")i ++;
    if(token[i] != "=")
    {
    	 ret[tolower(current_word)] = NULL; 
    }
    else
    {
    	i++;
	char = NULL;
	if(i >= len)break;
    	if(token[i] == '"')char = '"';
	else if(token[i] == "'")char = "'";
	
	if(!isnull(char))
 	{
	 j = stridx(token, char, i + 1);
	 if(j < 0)
	  {
	  if(debug)display("PARSE ERROR 1\n");
	  return(ret); # Parse error
	  }
	 ret[tolower(current_word)] = substr(token, i + 1, j - 1);
	 while(j+1 < len &&  token[j+1]==" ")j++;
	 i = j;
	}
        else
        {
         j = stridx(token, ' ', i + 1);
	 if(j < 0)
	  {
	   j = strlen(token);
	  }
	 ret[tolower(current_word)] = substr(token, i, j - 1);
	 i = j;
       }
     }
   }
    current_word = "";
    word_index ++;
  }
  else {
        # Filter out non-ascii text 
  	if(i < len && ord(token[i]) < 0x7e && ord(token[i]) > 0x21 )current_word = current_word + token[i];

	# Too long token
	if ( strlen(current_word) > 64 ) return ret;
	}
 }
 
 if(!word_index)ret["nasl_token_type"] = tolower(current_word);
 return ret;
}


#-------------------------------------------------------------------------#

function parse_java(elements) 
{
    local_var archive, code, codebase;

    archive = elements["archive"];
    code = elements["code"];
    codebase = elements["codebase"];

    if (codebase) 
    {
         if (archive)
            set_kb_item(name:string("www/", port, "/java_classfile"), value:string(codebase,"/",archive));
         if (code)
             set_kb_item(name:string("www/", port, "/java_classfile"), value:string(codebase,"/",code));
    } 
    else 
    {
         if (archive)
            set_kb_item(name:string("www/", port, "/java_classfile"), value:archive);
         if (code)
            set_kb_item(name:string("www/", port, "/java_classfile"), value:code);
    }
}







function parse_javascript(elements, current)
{
  local_var url, pat;
  
  if(debug > 15)display("*** JAVASCRIPT\n");
  
  pat = string("window\\.open\\('([^',", raw_string(0x29), "]*)'.*\\)*");
  url = ereg_replace(pattern:pat,
  		     string:elements["onclick"],
		     replace:"\1",
		     icase:TRUE);
		
  	     
  if( url == elements["onclick"])
   return NULL;
  
  url = canonical_url(url:url, current:current); 
  if( url )
  {
   add_url(url : url);
   return url;
  }
  
  return NULL;
}


function parse_dir_from_src(elements, current)
{
 local_var src, dir;
 
 src = elements["src"];
 if( ! src ) return NULL;
 
 src = canonical_url(url:src, current:current);
 dir = dir(url:src);
 if(dir && !Dirs[dir])
 {
  Dirs[dir] = 1;
  set_kb_item(name:string("www/", port, "/content/directories"), value:dir);
  if(isnull(URLs_hash[dir]))
   {
    URLs = make_list(URLs, dir);
    URLs_hash[dir] =  0;
   }
  }
}


function parse_href_or_src(elements, current)
{
 local_var href;
 
 href = elements["href"];
 if(!href)href = elements["src"];
 
 if(!href){
	return NULL;
	}
 
 href = canonical_url(url:href, current:current);
 if( href )
 {
  add_url(url: href);
  return href;
 }
}


function parse_refresh(elements, current)
{
 local_var href, content, t, sub;
 
 content = elements["content"];
 
 if(!content)
  return NULL;
 t = strstr(content, ";");
 if( t != NULL ) content = substr(t, 1, strlen(t) - 1);
 
 content = string("a ", content);
 sub = token_parse(token:content);
 
 if(isnull(sub)) return NULL;
 
 href = sub["url"];
 if(!href)
  return NULL;
 
 href = canonical_url(url:href, current:current);
 if ( href )
 {
  add_url(url: href);
  return href;
 }
}


function parse_form(elements, current)
{
 local_var action;
 
 action = elements["action"];
 
 action = canonical_url(url:action, current:current);
 if ( action )
   return action;
 else 
   return NULL;
}


function pre_parse(data, src_page)
{
    local_var php_path, fp_save, data2;

    if ("Index of /" >< data)
    {
    	    if(!Misc[src_page])
	    {
	    if("?D=A" >!< src_page && "?PageServices" >!< src_page)
	    	{
             	 misc_report = misc_report + string("Directory index found at ", src_page, "\n");
	   	 Misc[src_page] = 1;
		 }
	    }
    }
    
    if ("<title>phpinfo()</title>" >< data)
    {
    	    if(!Misc[src_page])
	    {
            misc_report = misc_report + string("Extraneous phpinfo() script found at ", src_page, "\n"); 
	    Misc[src_page] = 1;
	    }
            
    }
    
    if("Fatal" >< data || "Warning" >< data)
    {
    data2 = strstr(data, "Fatal");
    if(!data2)data2 = strstr(data, "Warning");
    
    data2 = strstr(data2, "in <b>");
    if ( data2 ) 
    {
    php_path = ereg_replace(pattern:"in <b>([^<]*)</b>.*", string:data2, replace:"\1");
    if (php_path != data2)
    {
        if (!Misc[src_page])
        {
            misc_report = misc_report + string("PHP script discloses physical path at ", src_page, " (", php_path, ")\n");
	    Misc[src_page] = 1;
        }
     }
    }
   }
    
   
    data2 = strstr(data, "unescape");
    
    if(data2 && ereg(pattern:"unescape..(%([0-9]|[A-Z])*){200,}.*", string:data2))
    {
     if(!Misc[src_page])
     {
      misc_report += string(src_page, " seems to have been 'encrypted' with HTML Guardian\n");
      guardian ++;
     }
    }
    
    if("CREATED WITH THE APPLET PASSWORD WIZARD WWW.COFFEECUP.COM" >< data)
    {
     if(!Misc[src_page])
     {
      misc_report += string(src_page, " seems to contain links 'protected' by CoffeCup\n");
      coffeecup++;
     }
     
      
    }

    if("SaveResults" >< data)
    { 
    fp_save = ereg_replace(pattern:'(.*SaveResults.*U-File=)"(.*)".*"', string:data, replace:"\2");
    if (fp_save != data)
     {
        if (!Misc[src_page])
        {
            misc_report = misc_report + string("FrontPage form stores results in web root at ", src_page, " (", fp_save, ")\n");
	    Misc[src_page] = 1;
        }   
     }
   }
}



function parse_main(current, data)
{
 local_var tokens, elements, cgi, form_cgis, form_cgis_level, args, store_cgi;
 local_var argz, token;
 
 form_cgis = make_list();
 form_cgis_level = 0;
 argz = NULL;
 store_cgi = 0;
 tokens = token_split(content: data);
 foreach token (tokens)
 {
   elements = token_parse(token:token);
   if(!isnull(elements))
   {
    
    if(elements["onclick"])
    	parse_javascript(elements:elements, current:current);

    if ( elements["nasl_token_type"] == "applet")
        parse_java(elements:elements);
	
    if(elements["nasl_token_type"] == "a" 	  || 
       elements["nasl_token_type"] == "link" 	  ||
       elements["nasl_token_type"] == "frame"	  ||
       elements["nasl_token_type"] == "iframe"	  ||
       elements["nasl_token_type"] == "area")
        if( parse_href_or_src(elements:elements, current:current) == NULL) {
	  if(debug > 20)display("ERROR - ", token, "\n");
	  }
    if(elements["nasl_token_type"] == "img")
    	parse_dir_from_src(elements:elements, current:current);
	
    if(elements["nasl_token_type"] == "meta")
    	parse_refresh(elements:elements, current:current);
			  
    if( elements["nasl_token_type"] == "form" )
    {
      cgi = parse_form(elements:elements, current:current);
      if( cgi )
      {
       form_cgis[form_cgis_level] = cgi;
       store_cgi = 1;
      }
      form_cgis_level ++;
    }
    
   if( elements["nasl_token_type"] == "/form")
    {
     form_cgis_level --;
     if( store_cgi != 0) add_cgi(cgi:form_cgis[form_cgis_level], args:argz);
     argz = "";
     store_cgi = 0;
    } 
   
   if( elements["nasl_token_type"] == "input" ||
       elements["nasl_token_type"] == "select")
    {
     if(elements["name"])
    	 argz += string( elements["name"], " [", elements["value"], "] ");
    }
   }
 }
}


#----------------------------------------------------------------------#
#				MAIN()				       #
#----------------------------------------------------------------------#




start_page = script_get_preference("Start page : ");
if(isnull(start_page) || start_page == "")start_page = "/";


max_pages = int(script_get_preference( "Number of pages to mirror : " ));
if(max_pages <= 0)
  if (COMMAND_LINE)
   max_pages = 9999;
  else
   max_pages = 30;

dirs = get_kb_list(string("www/", port, "/content/directories"));



num_cgi_dirs = 0;
if ( thorough_tests ) 
	max_cgi_dirs = 1024;
else 
	max_cgi_dirs = 4;


debug = 0;

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

URLs = make_list(start_page);
if(dirs) URLs = make_list(start_page, dirs);
URLs_hash[start_page] = 0;


ID_WebServer = 0;
Apache = 0;
iPlanet = 0;

CGIs = make_list();
Misc = make_list();
Dirs = make_list();

CGI_Dirs_List = make_list();

URLs_30x_hash = make_list();
URLs_auth_hash = make_list();


Code404 = make_list();

misc_report = "";
cnt = 0;

RootPasswordProtected = 0;

guardian  = 0;
coffeecup = 0;

foreach URL (URLs)
{ 
 if(!URLs_hash[URL])
 {
 	page = retr(port:port, page:URL);
	if (!isnull(page)) {
	  cnt ++;
	  pre_parse(src_page:URL, data:page);
	  parse_main(data:page, current:URL);
 	  URLs_hash[URL] = 1;
	  if(cnt >= max_pages)break;
	}
 }
}


if(cnt == 1)
{
 if(RootPasswordProtected)
 {
  set_kb_item(name:string("www/", port, "/password_protected"), value:TRUE);
 }
}
#foreach URL (URLs)
#{
# display(URL,"\n");
#}

#display("-----------------------------------------\n");


report = "";

foreach foo (keys(CGIs))
{
 args = CGIs[foo];
 if(!args) args = "";
 set_kb_item(name:string("www/", port, "/cgis"), value:string(foo, " - ", args));
 
  
 if(!report) 
 	report = string("The following CGI have been discovered :\n\nSyntax : cginame (arguments [default value])\n\n", foo, " (", args, ")\n");
 else
 	report = string(report, foo, " (", args, ")\n");

 if ( strlen(report) > 40000 ) break;
}

if(misc_report)
{ 

 report =  string(report, "\n\n", misc_report);
}


if(guardian)
{
 report += string("
 
HTML Guardian is a tool which claims to encrypt web pages, whereas it simply
does a transposition of the content of the page. It is is no way a safe
way to make sure your HTML pages are protected.

See also : http://www.securityfocus.com/archive/1/315950
BID : 7169");
}


if(coffeecup)
{
 report += "
 
CoffeeCup Wizard is a tool which claims to encrypt links to web pages,
to force users to authenticate before they access the links. However,
the 'encryption' used is a simple transposition method which can be 
decoded without the need of knowing a real username and password.

BID : 6995 7023";
}

if(strlen(report))
{
 security_note(port:port, data:report);
}

