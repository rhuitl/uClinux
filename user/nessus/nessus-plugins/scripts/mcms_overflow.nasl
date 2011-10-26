#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#
# Supercedes MS02-010
#
# Thanks to Dave Aitel for the details.
#
# also covers CVE-2002-0700

if(description)
{
 script_id(11313);
 script_bugtraq_id(4157, 4853, 5108, 5111, 5112);
 script_version ("$Revision: 1.17 $");
 
 script_cve_id("CVE-2002-0620", 
 	       "CVE-2002-0621", 
	       "CVE-2002-0622", 
	       "CVE-2002-0623",
	       "CVE-2002-0050");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-B-0007");
 
 name["english"] = "MCMS : Buffer overflow in Profile Service";
 script_name(english:name["english"]);
 
 desc["english"] = "

The remote host is running Microsoft Content Management Server.

There is a buffer overflow in the Profile Service which may
allow an attacker to execute arbitrary code on this host.


Solution : See http://www.microsoft.com/technet/security/bulletin/ms02-041.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of MCMS";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}



include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

if(!is_cgi_installed_ka(port:port, item:"/NR/System/Access/ManualLoginSubmit.asp"))exit(0);

payload = string("NR_DOMAIN=WinNT%3A%2F%2F0AG4ZA0SR80BCRG&NR_DOMAIN_LIST=WinNT%3A%2F%2F0AG4ZA0SR80BCRG&NR_USER=Administrator&NR_PASSWORD=asdf&submit1=Continue&NEXTURL=%2FNR%2FSystem%2FAccess%2FDefaultGuestLogin.asp");
req = http_post(item:"/NR/System/Access/ManualLoginSubmit.asp", port:port);
idx = stridx(req, string("\r\n\r\n"));
req = insstr(req, string("\r\nContent-Type: application/x-www-form-urlencoded\r\n",
      		 	 "Content-Length: ", strlen(payload), "\r\n\r\n"), idx);

req = string(req, payload);
soc = http_open_socket(port);
if(!soc)exit(0);
send(socket:soc, data:req);

r = recv_line(socket:soc, length:4096);
http_close_socket(soc);

if(!r) { security_hole(port); exit(0); }
if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 500 .*", string:r))security_hole(port);
