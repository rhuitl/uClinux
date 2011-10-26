#
# (C) Tenable Network Security
#
# XXXX Untested
#
# Ref:
# From:   officerrr@poligon.com.pl
# Subject: HotNews arbitary file inclusion
# Date: January 4, 2004 3:45:59 AM CET
# To:   bugtraq@securityfocus.com

if(description)
{
 script_id(11979);
 script_version ("$Revision: 1.5 $");

 name["english"] = "HotNews code injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running HostNews, a set of PHP scripts designed to set up
a newssystem for web pages.

It is possible this suite to make the remote host include php files hosted
on a third party server.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server.

Solution : Upgrade to the latest version of HotNews
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of HotNews";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");

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
if(!can_host_php(port:port))exit(0);





foreach dir (cgi_dirs())
 {
 req = http_get(item:string(dir, "/includes/hnmain.inc.php3?config[incdir]=http://xxxxxxxxxx/"),
 		port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL ) exit(0);
 if("http://xxxxxxxxxx/func.inc.php3" >< r)
  {
 	security_hole(port);
	exit(0);
  }
}
