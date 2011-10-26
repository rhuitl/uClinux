#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref:
#
# From: "BrainRawt ." <brainrawt@hotmail.com>
# To: bugtraq@securityfocus.com
# Subject: CGI-City's CCGuestBook Script Injection Vulns
# Date: Sat, 29 Mar 2003 18:47:04 +0000



if(description)
{
 script_id(11503);
 script_bugtraq_id(7237);
 script_version ("$Revision: 1.7 $");


 name["english"] = "cc_guestbook.pl XSS";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a perl script is vulnerable to a cross site
scripting vulnerability.

Description : 

The remote host is running cc_guestbook.pl, a guestbook written in Perl.


This CGI is vulnerable to a cross-site scripting attack.
An attacker may use this flaw to steal the cookies of your users.


Solution : 

Delete this CGI

Risk factor : 

Low / CVSS Base Score : 3 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of view.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
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

if(!get_port_state(port))exit(0);



foreach dir ( cgi_dirs() )
{
 req = http_get(item:string(dir, "/cc_guestbook.pl"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);

 if( res == NULL ) exit(0);

 if("Please enter a valid email address" >< res &&
    "Please enter your homepage title" >< res)
 	{
	security_note(port);
	exit(0);
	}
}
