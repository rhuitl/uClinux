#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#
# Added some extra checks. Axel Nennker axel@nennker.de

if(description)
{
 script_id(11370);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-1999-1376");

 name["english"] = "fpcount.exe overflow";
 script_name(english:name["english"]);
 
 # Description
 desc["english"] = "
There might be a buffer overflow in the remote
fpcount.exe cgi.

*** Nessus did not actually check for this flaw,
*** but solely relied on the presence of this CGI
*** instead

An attacker may use it to execute arbitrary code
on this host.

Solution : delete it
Risk factor : High";

 script_description(english:desc["english"]);

 # Summary
 summary["english"] = "Is fpcount.exe installed ?";
 script_summary(english:summary["english"]);

 # Category
 script_category(ACT_GATHER_INFO); 

 # Dependencie(s)
 script_dependencie("find_service.nes", "no404.nasl");
 
 # Family
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 
 # Copyright
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 
 script_require_ports("Services/www", 80);
 exit(0);
}

# The attack starts here
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);



req = http_get(item:"/_vti_bin/fpcount.exe", port:port);
res = http_keepalive_send_recv(port:port, data:req);

if( res == NULL ) exit(0);
if(("Microsoft-IIS/4" >< res) && ("HTTP/1.1 502 Gateway" >< res) )
	security_hole(port);
