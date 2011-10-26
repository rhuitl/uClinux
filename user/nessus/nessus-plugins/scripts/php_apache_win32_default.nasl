#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10839);
 script_cve_id("CVE-2002-2029");
 script_bugtraq_id(3786);
 script_version ("$Revision: 1.10 $");
 name["english"] = "PHP.EXE / Apache Win32 Arbitrary File Reading Vulnerability";
 name["francais"] = "PHP.EXE / Apache Win32 Arbitrary File Reading Vulnerability";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
A configuration vulnerability exists for PHP.EXE cgi running on Apache 
for Win32 platforms. It is reported that the installation text recommends 
configuration options in httpd.conf that create a security vulnerability, 
allowing arbitrary files to be read from the host running PHP. Remote users 
can directly execute the PHP binary:

http://www.somehost.com/php/php.exe?c:\winnt\win.ini

Solution: Obtain the latest version from http://www.php.net

References:
http://www.securitytracker.com/alerts/2002/Jan/1003104.html
http://www.php.net

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for PHP.EXE / Apache Win32 Arbitrary File Reading Vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002 Matt Moore",
		francais:"Ce script est Copyright (C) 2002 Matt Moore");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{ 	      
 if ( ! can_host_php(port:port) ) exit(0);
 req = http_get(item:"/php/php.exe?c:\winnt\win.ini", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("[windows]" >< r)	
 	security_hole(port);

 }
}
