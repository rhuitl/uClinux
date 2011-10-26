# -*- Fundamental -*-
#
# (C) 2002 Michel Arboi <arboi@alussinan.org>
# get_http_port (C) Georges Dagousset
# $Revision: 1.96 $

function headers_split(h)
 {
  local_var ret, array, item, subarray, end;
  end = strstr(h, '\r\n\r\n');
  if ( end ) h -= end;
 
  array = split(h, keep:FALSE);
  foreach item (array) 
  {
   subarray = split(item, sep:':', keep:FALSE);
   ret[tolower(subarray[0])] = ereg_replace(pattern:"^ *", replace:"", string:subarray[1]);
  }
 
  return ret;
 }
 
 



#
# That's for chunk-decoding
#
function __hex_value(num)
{
   if(num == "a")return(10);
   if(num == "b")return(11);
   if(num == "c")return(12);
   if(num == "d")return(13);
   if(num == "e")return(14);
   if(num == "f")return(15);
   return(int(num));
}


function hex2dec(xvalue)
{
 local_var ret, l, i, n, m;
  
 if(!xvalue)return(0);
 xvalue = tolower(xvalue);
 if ( '\r\n' >< xvalue )
 	l = strlen(xvalue) - 2;
 else if ( '\n' >< xvalue)
	l = strlen(xvalue) - 1;
 else   l = strlen(xvalue);

 
 ret = 0;
 m = 1;
 if ( l == 0 ) return 0;
 
 # Remove the trailing spaces
 while(xvalue[l - 1]==" " && l > 0)l--;
 
 for(i=l;i>0;i--)
 {
  n = __hex_value(num:xvalue[i - 1]) * m;
  ret = ret + n;
  m = m * 16;
 }
 return int(ret);
}

#---------------------------------------------------#

function get_http_banner(port)
{
  local_var soc, sb, banner, req, body;
  
  if ( get_kb_item("Services/www/" + port + "/broken") ) return NULL;
  
  if (! get_port_state(port)) return (0);
  sb = strcat("www/real_banner/", port);
  banner = get_kb_item(sb);
  if(banner) return(banner);
  
  sb = strcat("www/banner/", port);
  banner = get_kb_item(sb);
  if (banner) return(banner);

  soc = http_open_socket(port);
  if(!soc) return (NULL);
  req = http_get(item:"/", port:port);
  send(socket:soc, data:req);
  banner = http_recv_headers2(socket:soc);
  #body = http_recv_body(socket:soc, headers: banner);
  http_close_socket(soc);
  if(banner)
  {
   if ( defined_func("replace_kb_item") )
  	replace_kb_item(name: sb, value: banner);
   else
  	set_kb_item(name: sb, value: banner);
  }
  return(banner);
}

# Submitted by Georges Dagousset
# Usage: port = get_http_port(default:80);
function get_http_port(default)
{
  local_var	soc, port, p, r, then, now;

  if ( defined_func("unixtime") )
	then = unixtime();

  port = get_kb_item("Services/www");
  if ( port ) default = port;

  p = get_kb_item("Services/www/" + default + "/broken");
  if ( p ) exit(0);

  

  p = get_kb_item("Services/www/" + default + "/working");
  if ( p ) return default;

  if (! get_port_state(default)) exit(0);

  soc = http_open_socket(default);
  if ( ! soc ) 
  {
   set_kb_item(name:"Services/www/" + default + "/broken", value:1);
   exit(0);
  }

  send(socket:soc, data:'GET / HTTP/1.1\r\nHost: ' + get_host_name() + '\r\n\r\n');
  r = recv_line(socket:soc, length:4096);
  close(soc);
  if ( defined_func("unixtime") )
	now = unixtime();
  if ( ! r || "HTTP" >!< r || ( ereg(pattern:"^HTTP.* 403 ", string:r) && (now - then >= 5)  ) || ( ereg(pattern:"^HTTP.* 400 ", string:r) && default == 5000 ) || ( r == "HTTP/1.0" && port == 2381 ) )
  {
   set_kb_item(name:"Services/www/" + default + "/broken", value:1);
   exit(0);
  }

  
  set_kb_item(name:"Services/www/" + default + "/working", value:1);
  return default;
}

# (C) Georges Dagousset
# Usage:
# banner = get_http_banner(port:port);
# if (php_ver_match(banner:banner, 
#     pattern:".*PHP/((3.*)|(4\.0.*)|(4\.1\.[01].*))"))
#       security_hole(port);
#
function php_ver_match(banner, pattern) 
{
  local_var	line;
  line = egrep(pattern:"^Server:.*", string:banner);
  if(ereg(pattern:pattern, string:line))return(1);
  else
  {
    line = egrep(pattern:"^X-Powered-By:.*", string:banner);
    if(ereg(pattern:pattern, string:line))return(1);
  }
  return(0);
}

function http_is_dead(port, retry)
{
  local_var	soc, url, req, code, h, h2, b, i;
  
  if(!retry)retry = 2;

  i = 0;
  soc = http_open_socket(port);
  while (!soc && i++ < retry)
  {
    sleep(1);	# Should we use sleep(i) ?
    soc = http_open_socket(port);
    #display("i = ", i, "\n");
  }
  if (! soc) return (1);
  # NB: http_head does not work against SWAT & VNC (& probably others...)
  url = strcat("/NessusTest", rand(), ".html");
  req = http_get(item: url, port:port);
  
  send(socket:soc, data:req);
  code = recv_line(socket:soc, length: 1024);
  if (code)
  {
    h = http_recv_headers2(socket:soc);
    h2 = strcat(code, h);
    b = http_recv_body(socket: soc, headers: h2);
  }
  http_close_socket(soc);
  if (! code) return (1);
  # 500: internal server error
  # 501: not implemented = unsupported method...
  # 502: Bad gateway = upstream server sends an invalid response
  # 503: service unavailable = temporary overloading...
  # 504: gateway timeout = no timely response from upstream server
  if (ereg(pattern: "^HTTP/1\.[01] +50[234]", string: code)) return(1);
  return (0);
}

# This function was originaly written by SecurITeam in 
# badblue_directory_traversal.nasl
# I (=MA) enhanced it.
# NB: it works with AUTOEXEC.BAT, WIN.INI and BOOT.INI
# quickcheck should be set to 0 if the server does not return clean 404 code,
# i.e., if "www/no404/"+port is defined in the KB

function do_check_win_dir_trav(port, url, quickcheck)
{
  local_var	soc, req, cod, buf;
  #display("check_win_dir_trav(port=", port, ", url=", url, ", quickcheck=", quickcheck, ")\n");
  soc = http_open_socket(port);
  if(! soc)
  {
   # display("check_win_dir_trav: cannot open socket to ", port, "\n");
    return (0);
  }

  req = http_get(item:url, port:port);
  send(socket:soc, data:req);
  cod = recv_line(socket: soc, length: 80);
  buf = http_recv(socket:soc, code: cod);
  http_close_socket(soc);

  if (quickcheck)
  {
    if (" 200 " >< cod) return (1);
    return (0);
  }

  if ( "; for 16-bit app support" >< buf )
  {
    return(1);
  }
  return(0);
}

function check_win_dir_trav(port, url, quickcheck)
{
 if(do_check_win_dir_trav(port:port, url:url + rand(), quickcheck:quickcheck))
	return NULL;
 else
	return do_check_win_dir_trav(port:port, url:url, quickcheck:quickcheck);
}

function http_recv_headers2(socket)
{
 local_var buf, line, counter;
 while ( TRUE )
 {
  counter ++;
  line = recv_line(socket:socket, length:4096);
  buf += line;
  if ( line == '\r\n' ) break;
  if ( ! strlen(line) ) break;
  if ( counter > 1024 ) break;
 }

 return buf;
}


# This function does not return the headers!
# So 'length' parameter does not include headers length, even if we 
# have to read them. 
# If Content-length is set, "length" only allows the function to read 
# more data, if available. i.e., it is ignored most of the time.
#

function http_recv_body(socket, headers, length)
{
  local_var	h, cl, l, min, max, x, n, to, dobrk;
  if (!headers)
  {
    h = http_recv_headers2(socket:socket);
  }
  else
  {
    h = headers;
  }

  l = -1;
  cl = egrep(pattern:"^Content-length: *[0-9]+", string: h, icase: 1);
  if(cl)
  {
    l = int(ereg_replace(pattern: "Content-length: *([0-9]+).*", replace:"\1",
		string: cl, icase: 1));
  }
  # "l" = Content-Length or -1 now

  max = -1;
  min = -1;
  

  if(l < 0 && egrep(pattern:"^transfer-encoding: chunked", string:h, icase:TRUE))
  {
   local_var tmp, body;
   body = "";
 
   dobrk = 0;
   while(1)
   {
   tmp = recv_line(socket:socket, length:4096);
   l = hex2dec(xvalue:tmp);
   if ( l >= 1048576 ) 
   {
	l = 1048576;
	dobrk = 1;
   }
   body  = strcat(body, recv(socket:socket, length:l, min:l));
   # "\r\n"
   recv (socket:socket, length:2, min:2);
   if(l == 0 || dobrk != 0 ){
   	return(body); # This is expected - don't put this line before the previous
	}
   }
  }
  
  
  if (length) max = length;
  if (l >= 0) min = int(l);
  if (l >= max || min >= max ) max = l;
  if ( max < 0 || max > 1048576 )
  {
    #display("http_recv_body: bogus or no Content-length field, and no 'length' parameter set! Defaulting to 8 KB\n");
    max = 8192;
  }
 
  #display("http_recv_body: min=", min, "; max=", max, "\n");
  if (min > 0)
  {
    x = recv(socket: socket, length: max, min: min);
  }
  else
  {
    n = recv(socket: socket, min:max, length: max);
    x = n;
    while ( strlen(n) >= max && max != 0 )
    {
     n = recv(socket: socket, length: max);
     x += n;
     if( strlen(x) > 1048576){
        display("http_recv_body: read stopped after 1 MB!\n");
	break;
	}
    }
  }

  return(x);
}

# This function reads everything
# Note that bodylength will be ignored if the Content-length field is set

function http_recv(socket, code)
{
  local_var	h, b, l;
  if (code)
  {
    h = strcat(code);	# Convert to string, just in case
    repeat
    {
      l = recv_line(socket: socket, length: 2048);
      h = h + l;
    }
    until (! l || l =~ '^[\r\n]+$'); # EOF or empty line
    if (!l) return h;
  }
  else
  {
    h = http_recv_headers2(socket:socket);
    if(!h) return(NULL);
    else if ( ! ereg(pattern:"^HTTP/.* [0-9]*", string:h) ) return h;
    h = strcat(h, '\r\n');
  }
  b = http_recv_body(socket: socket, headers: h, length:0);
  return strcat(h, b);
}

function http_recv_length(socket, bodylength)
{
  local_var	h, b;
  h = http_recv_headers2(socket:socket);
  b = http_recv_body(socket: socket, headers: h, length: bodylength);
  return strcat(h, '\r\n', b);
}

function http_send_recv(port, data)
{
  local_var	s, r;

  s = http_open_socket(port);
  if (! s) return;
  send(socket: s, data: data);
  r = http_recv(socket: s);
  http_close_socket(s);
  return r;
}


function cgi_dirs()
{
 local_var kb;
 if ( get_kb_item("Settings/disable_cgi_scanning") ) return make_list();

 kb = get_kb_list("/tmp/cgibin");
 if(isnull(kb))kb = make_list("/cgi-bin", "/scripts", "");
 else kb = make_list(kb, "");
 
 return(kb); 
}




function can_host_php(port)
{
 local_var banner, sig, files;

 if ( get_kb_item("Services/www/" + port + "/embedded") ) return 0;

 banner = get_http_banner(port:port);
 if ( ! banner ) return 0;
 else 
 {
  if ( egrep(pattern:"^Server:.*IceWarp", string:banner, icase:1 ) )
    return 1;

 if ( egrep(pattern:"^Server:.*apache|thttpd|aolserver|pi3web|zeus|iis", string:banner, icase:1 ) )
		{
		#display(get_host_ip(), " may host PHP\n");
		return 1;
		}
 }

 files = get_kb_list("www/" + port + "/content/extensions/php*");
 if ( !isnull(files) ) {
		#display(get_host_ip(), " hosts PHP - ", files[0], "\n");
		return 1; # Hosting .php+ files
	 	}	


 sig = get_kb_item("www/hmap/" + port + "/description");
 if ( ! sig ) { 
	#display(get_host_ip(), " has no sig\n"); 
  	# If it has a banner but did not match above, then declare this is not a PHP
	# web site (dangerous, so disabled)
	#if ( egrep(pattern:"^Server:.*", string:banner) ) return 0;
	#else 
	 return 1; # Unknown web server - might be able to host a PHP website
	}

 if ( egrep(pattern:"apache|thttpd|aolserver|pi3web|zeus|iis", string:sig, icase:1 ) )
	{
	#display(get_host_ip(), " may be PHP site (sig)\n");
	return 1;
	}
 else {
	#display(get_host_ip(), " is definitely NOT a PHP site (sig) - ", sig, "\n");
	return 0;
	}
}

function can_host_asp(port)
{
 local_var banner, sig, files;

 if ( get_kb_item("Services/www/" + port + "/embedded") ) return 0;

 banner = get_http_banner(port:port);
 if ( ! banner ) return 0;
 else 
 {
 if ( egrep(pattern:"^Server:.*IIS", string:banner, icase:1 ) )
		{
		#display(get_host_ip(), " may host ASP\n");
		return 1;
		}
 }

 files = get_kb_list("www/" + port + "/content/extensions/asp");
 if ( !isnull(files) ) {
		#display(get_host_ip(), " hosts ASP - ", files[0], "\n");
		return 1; # Hosting .asp files
	 	}	


 sig = get_kb_item("www/hmap/" + port + "/description");
 if ( ! sig ) { 
	#display(get_host_ip(), " has no sig\n"); 
  	# Could not fingerprint it, even though we know that IIS fingerprint
        # is quite reliable 
	if ( egrep(pattern:"^Server:.*", string:banner) ) return 0;
	else 
	 return 1; # Unknown web server - might be able to host a ASP website
	}

 if ( egrep(pattern:"iis", string:sig, icase:1 ) )
	{
	#display(get_host_ip(), " may be ASP site (sig)\n");
	return 1;
	}
 else {
	#display(get_host_ip(), " is definitely NOT a ASP site (sig) - ", sig, "\n");
	return 0;
	}
}

function http_40x(port, code)
{
  local_var	no404;

  if (ereg(string: code, pattern: "^HTTP/1\.[01] +40[0-9]"))
   return TRUE;

  no404 = get_kb_item("www/no404/"+port);
  if (no404 && no404 >< code)
    return TRUE;
  return FALSE;
}
