#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref: 
# Subject : MPCSoftWeb Guest Book vulnerabilities.
# From: drG4njubas (drG4njmail.ru)
# Date: Sun Apr 20 2003 - 08:15:51 CDT 



if(description)
{
 script_id(11590);
 script_bugtraq_id(7389, 7390);
 script_version ("$Revision: 1.8 $");
 
 name["english"] = "MPC SoftWeb Guestbook database disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server is running MPCSoftwebGuestbook a set of .asp
scripts to manage an online guestbook.

This release comes with a database called 'mpcsoftware_guestdata.mdb', 
usually located under /database/ which contains sensitive information, 
such as the news site administrator password.

An attacker may use this flaw to gain unauthorized access to the 
remote site and potentially edit it.

Note that this server is also vulnerable to a cross-site-scripting
attack which allows an attacker to have javascript code executed on
the browser of other hosts.

Solution : Prevent the download of .mdb files from your website.
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for mpcsoftware_guestdata.mdb";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);


foreach d (cgi_dirs())
{
 req = http_get(item:string(d, "/database/mpcsoftware_guestdata.mdb"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 
 if ( res == NULL ) exit(0);
 
 if("Standard Jet DB" >< res)
	{
 	 security_warning(port);
	 exit(0);
	 }
}
