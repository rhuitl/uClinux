#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref:
#  Date: 20 Mar 2003 03:33:03 -0000
#  From: subj <r2subj3ct@dwclan.org>
#  To: bugtraq@securityfocus.com
#  Subject: SimpleChat



if(description)
{
 script_id(11469);
 script_bugtraq_id(7168);
 script_version ("$Revision: 1.6 $");


 name["english"] = "SimpleChat information disclosure";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to retrieve list of users currently connected to
the remote SimpleChat server by requesting the file data/usr.

An attacker may use this flaw to obtain the IP address of every
user currently connected and possibly harass them directly.

Solution : None at this time. Add a .htaccess file to prevent an attacker
from obtaining this file

Risk factor : Low";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of data/usr";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
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

if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 req = http_get(item:string(dir, "/data/usr"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);

 if( res == NULL ) exit(0);

 if(ereg(pattern:"HTTP/.\.. 200 ", string:res))
 {
  if(egrep(pattern:"[0-9]+:\|:[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:\|", string:res))
  {
   security_warning(port);
   exit(0);
  }
 }
}
