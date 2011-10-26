#
# This script is (C) Tenable Network Security
#
# 
# Ref: 
#  From: "Marc Bromm" <theblacksheep@fastmail.fm>
#  To: bugtraq@securityfocus.com
#  Date: Mon, 09 Jun 2003 09:25:19 -0800
#  Subject: Several bugs found in "Spyke's PHP Board"


if(description)
{
 script_id(11706);
 script_bugtraq_id(7856);
 script_version ("$Revision: 1.7 $");

 name["english"] = "Spyke Flaws";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Spyke - a web board written in PHP.

This board stores vital information in the file info.dat,
which may be downloaded by anyone. This file contains
the name of the administrator of the web site, as well as
its password.

Another flaw lets an attacker download any information about
any user simply by knowing their name.

Solution : None at this time.
Risk factor : Medium";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of info.dat";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes","http_version.nasl");
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



function check(loc)
{
 req = http_get(item:string(loc, "/info.dat"),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if("$adminpw" >< r )
 {
 	security_warning(port);
	exit(0);
 }
}


foreach dir (cgi_dirs())
{
 check(loc:dir);
}
