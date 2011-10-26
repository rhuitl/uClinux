#
# (C) Tenable Network Security
#
# Ref: 
# From: "Bojan Zdrnja" <Bojan.Zdrnja@LSS.hr>
# To: <bugtraq@securityfocus.com>
# Subject: Remote execution in My_eGallery
# Date: Thu, 27 Nov 2003 09:37:36 +1300
#


if(description)
{
 script_id(11931);
 script_bugtraq_id(9113);
 script_version ("$Revision: 1.8 $");
 name["english"] = "My_eGallery code execution";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to make the remote host execute arbitrary code by abusing
the my_egallery PostNuke module running on this host.

An attacker may use this flaw to execute arbitrary code in the remote
host and gain a shell with the privileges of the web server.

Solution : Upgrade to My_eGallery 3.1.1g or newer
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the version of My_eGallery";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
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

foreach dir (cgi_dirs())
{
 req = http_get(item:dir + "/modules.php?name=My_eGallery", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);

 if (egrep(pattern:"Powered by: My_eGallery ([0-2]\.|3\.0\.|3\.1\.0|3\.1\.1\.?[a-f])", string:res)) { security_hole(port); exit(0); }
}
