#
# Copyright 2000 by Renaud Deraison <deraison@nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10582);
 script_version ("$Revision: 1.21 $");
 
 name["english"] = "HTTP version spoken";
 script_name(english:name["english"]);
 
 desc["english"] = "
This script determines which version of the HTTP protocol the remote
host is speaking

Risk factor : None";

 script_description(english:desc["english"]);
 
 summary["english"] = "HTTP version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("apache_SSL_complain.nasl", "doublecheck_std_services.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("misc_func.inc");

port = get_http_port(default:80);


function mkreq(ua, item)
{
 if ( isnull(item) ) item = "/";
 return string("GET ", item, " HTTP/1.1\r\n",
  	      "Connection: Close\r\n",
  	      "Host: ", get_host_name(), "\r\n",
	      "Pragma: no-cache\r\n",
	      "User-Agent: " + ua + "\r\n",
	      "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\n",
	      "Accept-Language: en\r\n",
	      "Accept-Charset: iso-8859-1,*,utf-8\r\n",
	      "\r\n"
	      ); 
}

function check_ips(port)
{
 local_var soc, req;
 local_var r;

 req = mkreq(ua:"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)");
 soc = http_open_socket(port);
 if ( ! soc ) return 0;
 send(socket:soc, data:req);
 r = http_recv_headers2(socket:soc);
 close(soc);

 if ( ! r ) return 0;
 if ( ! ereg(pattern:"^HTTP", string:r) ) return 0;

 soc = http_open_socket(port);
 if ( ! soc ) return 0;
 req = mkreq(ua:"Mozilla/4.75 [en] (X11; U; Nessus)");
 send(socket:soc, data:req);
 r = http_recv_headers2(socket:soc);
 close(soc);

 if ( ! r ) return 1;
 if ( ! ereg(pattern:"^HTTP", string:r) ) return 1;

 return 0;
}

function check_proxy(port)
{
 local_var soc, req;
 local_var r;
 
 req = mkreq(item:"http://www.google.com");
 soc = http_open_socket(port);
 if ( ! soc ) return 0;
 send(socket:soc, data:req);
 r = http_recv_headers2(socket:soc);
 close(soc);

 if ( egrep(pattern:"^Via: ", string:r) ) set_kb_item(name:"Services/http_proxy", value:port);
}




 if(get_port_state(port))
 {

  if ( check_ips(port:port) )
  {
   report = 
"The remote port seems to either have network connectivity issues
or seems to be protected by an IPS which prevents Nessus from 
sending HTTP requests to this port.

As a result, the remote web server will not be tested.

Solution : configure your IPS to allow network scanning from " + this_host() + "
Risk Factor : None";
  security_note(port:port, data:report);
  set_kb_item(name:"Services/www/" + port + "/broken", value:TRUE);
  exit(0);
  }
  soc = http_open_socket(port);
  if(!soc)exit(0);
  req = string("GET / HTTP/1.1\r\n",
  	      "Connection: Close\r\n",
  	      "Host: ", get_host_name(), "\r\n",
	      "Pragma: no-cache\r\n",
	      "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)\r\n",
	      "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\n",
	      "Accept-Language: en\r\n",
	      "Accept-Charset: iso-8859-1,*,utf-8\r\n",
	      "\r\n"
	      ); 
  send(socket:soc, data:req);
  r = http_recv_headers2(socket:soc);
  http_close_socket(soc);
  if ( ereg(string:r, pattern:"^HTTP/.* 30[0-9] ") &&
       egrep(pattern:"^Server: EZproxy", string:r) )
		{
   report = 
"The remote port seems to be running EZproxy, a proxy server which
opens many HTTP ports to simply to perform HTTP redirections.

Nessus will not perform HTTP tests again the remote port, since they
would consume time and bandwidth for no reason

See also : http://www.usefulutilities.com/support/rewrite.html";

  		 security_note(port:port, data:report);
  		 set_kb_item(name:"Services/www/" + port + "/broken", value:TRUE);
 		 exit(0);
		}

  if(ereg(string:r, pattern:"^HTTP/.* [0-9]*") )
   	{
  	set_kb_item(name:string("http/", port), value:"11");
	exit(0);
	}
  else 
  {
   soc = http_open_socket(port);
   if(!soc)exit(0);
   req = string("GET / HTTP/1.0\r\n\r\n");
   send(socket:soc, data:req);
   r = recv_line(socket:soc, length:4096);
   http_close_socket(soc);
  if(ereg(string:r, pattern:"^HTTP/.* [0-9]*") )
     {
   	set_kb_item(name:string("http/", port), value:"10");
	exit(0);
     }
   else
     {
       soc = http_open_socket(port);
       if(!soc)exit(0);
       req = string("GET /\r\n\r\n");
       send(socket:soc, data:req);
       r = recv_line(socket:soc, length:4096);
       http_close_socket(soc);
       if("HTML" >< r || "200" >< r)
         {
           set_kb_item(name:string("http/", port), value:"09");
	   exit(0);
         }
     }
  }
 }


# The remote server does not speak http at all. We'll mark it as
# 1.0 anyway
if(port == 80)
{
 set_kb_item(name:string("http/", port), value:"10");
}
