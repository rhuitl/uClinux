#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
#
# GPL
#
# Vulnerable servers:
# Pi3Web/2.0.0
#
# References
# Date:  10 Mar 2002 04:23:45 -0000
# From: "Tekno pHReak" <tek@superw00t.com>
# To: bugtraq@securityfocus.com
# Subject: Pi3Web/2.0.0 File-Disclosure/Path Disclosure vuln
#
# Date:	 Wed, 14 Aug 2002 23:40:55 +0400
# From:	"D4rkGr3y" <grey_1999@mail.ru>
# To:	bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: new bugs in MyWebServer
#	

if(description)
{
 script_id(11714);
 script_bugtraq_id(3341, 4035, 4261, 5054, 8075);
 # Note: the way the test is made will lead to detecting some
 # path disclosure issues which might be checked by other plugins 
 # (like #11226: Oracle9i jsp error). I have reviewed the reported
 # "path disclosure" errors from bugtraq and the following list
 # includes bugs which will be triggered by the NASL script. Some
 # other "path disclosure" bugs in webservers might not be triggered
 # since they might depend on some specific condition (execution
 # of a cgi, options..)
 # jfs - December 2003
 script_cve_id("CVE-2003-0456","CVE-2001-1372");
 
 script_version ("$Revision: 1.9 $");
 name["english"] = "Non-Existant Page Physical Path Disclosure Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
Your web server reveals the physical path of the webroot 
when asked for a non-existent page.

Whilst printing errors to the output is useful for debugging applications, 
this feature should not be enabled on production servers.

Solution : Upgrade your server or reconfigure it
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for a Generic Physical Path Disclosure Vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# 

include("http_func.inc");
include("http_keepalive.inc");

ext = make_list(".", "/", ".html", ".htm", ".jsp", ".asp", ".shtm", ".shtml",
		".php", ".php3", ".php4", ".cfm");

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);

foreach e (ext)
{
  f = string("niet", rand());
  req = http_get(item:string("/", f, e), port:port);
  r = http_keepalive_send_recv(port: port, data: req);
  if(isnull(r)) exit(0);	# Connection refused
  # Windows-like path
  if (egrep(string: r, pattern: strcat("[C-H]:(\\[A-Za-z0-9_.-])*\\", f, "\\", e)))
  {
    security_warning(port);
    exit(0);
   }
  # Unix like path
  if (egrep(string: r, pattern: strcat("(/[A-Za-z0-9_.+-])+/", f, "/", e)))
  {
    security_warning(port);
    exit(0);
   }
}
