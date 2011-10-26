#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref:
#  Date: 23 Mar 2003 02:24:23 -0000
#  From: subj <r2subj3ct@dwclan.org>
#  To: bugtraq@securityfocus.com
#  Subject: VChat



if(description)
{
 script_id(11471);
 script_bugtraq_id(7186, 7188);
 script_version ("$Revision: 1.6 $");



 name["english"] = "VChat information disclosure";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to retrieve the log of all the chat sessions
that have occured on the remote vchat server by requesting
the file vchat/msg.txt

An attacker may use this flaw to read past chat sessions and
possibly harass its participants.


In addition to this, another flaw in the same product may allow an attacker
to consume all the resources of the remote host by sending a long 
message to this module.

Solution : None at this time. Add a .htaccess file to prevent an attacker
from obtaining this file

Risk factor : Low";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of vchat/msg.txt";
 
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
 req = http_get(item:string(dir, "/msg.txt"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);

 if( res == NULL ) exit(0);

 if(egrep(pattern:"HTTP/.\.. 200 ", string:res))
 {
  if(egrep(pattern:"^<b>.* :</b>.*<br>$", string:res))
  {
   security_warning(port);
   exit(0);
  }
 }
}
