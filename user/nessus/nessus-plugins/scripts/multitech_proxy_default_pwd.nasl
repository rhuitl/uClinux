#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details



if(description)
{
 script_id(11504);
 script_cve_id("CVE-2002-1629");
 script_bugtraq_id(7203);
 
 script_version("$Revision: 1.5 $");
 
 name["english"] = "MultiTech Proxy Server Default Password";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote MultiTech Proxy Server has no password set for
the 'supervisor' account.

An attacker may log in the remote host and reconfigure it 
easily.

Solution : Set a password for the supervisor account.
Risk factor : High";
 script_description(english:desc["english"]);
 
 summary["english"] = "Attempts to log into the remote web server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Remote file access";
 
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);



req = http_get(item:"/std.html", port:port);
auth = egrep(pattern:"^Authorization", string:req);
if(auth) req = req - auth;
 
res = http_keepalive_send_recv(port:port, data:req);
if(res == NULL) exit(0);
 
if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 40[13] .*", string:res))
 { 
  idx = stridx(req, string("\r\n\r\n"));
  req = insstr(req, string("\r\nAuthorization: Basic c3VwZXJ2aXNvcjo=\r\n\r\n"), idx);
  
  res = http_keepalive_send_recv(port:port, data:req);
  if(res == NULL) exit(0);
  if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res))
  {
   security_hole(port);
   exit(0);
  }
 }
