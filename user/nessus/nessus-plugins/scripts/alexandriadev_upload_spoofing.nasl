#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref:
# From: Thomas Kristensen <tk@secunia.com>
# To: vulnwatch@vulnwatch.org
# Date: 28 Mar 2003 14:54:33 +0100
# Subject: [VulnWatch] Alexandria-dev / sourceforge multiple vulnerabilities


if(description)
{
 script_id(11498);
 script_bugtraq_id(7223, 7224, 7225);
 script_version ("$Revision: 1.10 $");



 name["english"] = "Alexandria-dev upload spoofing";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be running Alexandria-Dev, an open-sourced
project management system.

The CGIs docman/new.php and patch/index.php can be used by an attacker
with the proper credentials to upload a file and trick the server
about its real location on the disk. Therefore, an attacker may use
this flaw to read arbitrary files on the remote server.

*** Nessus solely relied on the presence of this CGI to issue
*** this alert, so this might be a false positive

Solution : None at this time
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of patch/index.php and docman/new.php";
 
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
if(!can_host_php(port:port)) exit(0);




dirs = make_list(cgi_dirs(), "/SF2.5", "/sf");



foreach dir (dirs)
{
 req = http_get(item:string(dir, "/docman/new.php"),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if("No group_id" >< r){security_hole(port); exit(0);}
 
 req = http_get(item:string(dir, "/patch/index.php"),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if("No Group Id" >< r){ security_hole(port); exit(0); }
}
