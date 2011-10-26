#
# (C) Tenable Network Security
#


if (description)
{
 script_id(14190);
 script_bugtraq_id(10793);
 script_version("$Revision: 1.3 $");

 script_name(english:"PostNuke Install Script");
 desc["english"] = "
The remote host is running the Post-Nuke content management system.

The installation script of the remote Post-Nuke CMS (install.php)
is accessible. An attacker may access it to reconfigure the remote 
PostNuke installation and obtain the password of the remote database
and postnuke installation.

Solution : Delete install.php
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Determines if post-nuke's install.php is readable");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 script_dependencie("postnuke_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

kb = get_kb_item("www/" + port + "/postnuke" );
if ( ! kb ) exit(0);
stuff = eregmatch(pattern:"(.*) under (.*)", string:kb );
dir = stuff[2];


req = http_get(item:string(dir, "/install.php"), port:port);
res = http_keepalive_send_recv(port:port, data:req);
if(res == NULL ) exit(0);
 
if("<title>PostNuke Installation</title>" >< res)
    	security_hole(port);
