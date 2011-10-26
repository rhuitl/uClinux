#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE
#
# I wonder if this script should not be merged with web_traversal.nasl
# References:
# From: john@interrorem.com
# Subject: Snapstream PVS vulnerability
# To: bugtraq@securityfocus.com
# Date: Thu, 26 Jul 2001 08:23:51 +0100 (BST)


if(description)
{
 script_id(11079);
 script_bugtraq_id(3100);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2001-1108");
 
 name["english"] = "Snapstream PVS web directory traversal";
 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to read arbitrary files on the remote 
Snapstream PVS server by prepending ../../ in front on the 
file name.
It may also be possible to read ../ssd.ini which contains
many informations on the system (base directory, usernames &
passwords).

Solution : Upgrade your software or change it!
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Snapstream web directory traversal";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");

 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8129);
 exit(0);
}

# FP + other Directory Traversal scripts do the same thing
exit (0);

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


port = get_http_port(default:8129);
if(!port) exit(0);

if(!get_port_state(port)) exit(0);

fil[0] = "/../ssd.ini";
fil[1] = "/../../../../autoexec.bat";
fil[2] = "/../../../winnt/repair/sam";

for (i=0; i<3; i=i+1) {
  ok = is_cgi_installed_ka(port:port, item:fil[i]);
  if (ok) { security_hole(port); exit(0); }
}


