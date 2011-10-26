#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref:
# Date: Wed, 27 Mar 2002 18:07:27 +0300
# From: Over_G <overg@mail.ru>
# Subject: Vulnerability in my guest book 
# To: vuln@security.nnov.ru, bugtraq@securityfocus.com
#
#
# This script check for a vulnerability which is used by at lease ONE 
# person in the world. Seriously, I wonder if it's really worth writing
# such scripts....


if(description)
{
 script_id(11489);
 script_bugtraq_id(7213);
 script_version ("$Revision: 1.8 $");

 name["english"] = "myguestbk admin access";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is hosting myGuestBook.

This installation comes with an administrative file
in myguestBk/admin/index.asp which lets any user
delete old entries.

In addition to this, this CGI is vulnerable to a cross-site-scripting
attack.

Solution : Restrict access to admin/index.asp
Risk factor : Low";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of admin/index.asp";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if ( ! can_host_asp(port:port) ) exit(0);





dirs = make_list(cgi_dirs(), "/myguestbk");



foreach dir (dirs)
{
 req = http_get(item:string(dir, "/admin/index.asp"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 
 if("Delete this Entry" >< res)
 {
  security_warning(port);
  exit(0);
 }
}
