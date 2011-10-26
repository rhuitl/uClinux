#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref: 
#  Date: Wed, 10 Apr 2002 08:05:53 +0400
#  From: Over_G <overg@mail.ru>
#  To: bugtraq@securityfocus.com
#  Subject: Disclosing information in Super GuestBook


if(description)
{
 script_id(11536);
 script_bugtraq_id(7319);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "Super Guestbook config disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server is running Super GuestBook, a set of php
scripts to manage an interactive guestbook.

An attacker may retrieve the file /superguestconfig, which contains
the password of the guestbook administrator as well as other configuration
details.

Solution : Prevent the download of superguestconfig
Risk factor : Low";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for superguestconfig";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);


if(!get_port_state(port))exit(0);


dirs = make_list(cgi_dirs(),  "/sgb");

foreach d (dirs)
{
 req = http_get(item:string(d, "/superguestconfig"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 
 if ( res == NULL ) exit(0);
 
 if("MultipleSign=" >< res &&
    "Header=" >< res &&
    "MyName=" >< res)
	{
 	 security_warning(port);
	 exit(0);
	 }
}
