#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11334);
 script_bugtraq_id(4412);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2002-0513");
 
 name["english"] = "popper_mod";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to administrate the remote popper_mod CGI
by requesting the /admin directory directly.

An attacker may use this flaw to obtain the passwords
of your users.

Solution : upgrade to the latest version
Risk factor : High";

 

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks if popper_mod is vulnerable";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "httpver.nasl");
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

foreach dir (make_list(cgi_dirs(), "/mail"))
{
 req = http_get(item:"/admin/", port:port);
 result = http_keepalive_send_recv(port:port, data:req);
 if(result == NULL) exit(0);
 
 # The typo below is included in the software.
 if("webmail Adminstration" >< result)security_hole(port);
}
