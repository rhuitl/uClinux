# This script was written by Renaud Deraison
#
# Ref :
# Date: Tue, 6 May 2003 19:14:40 -0700 (PDT)
# From: Dave Palumbo <dpalumbo@yahoo.com>
# To: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: [VulnDiscuss] XSS In Neoteris IVE Allows Session Hijacking
#
#
# Special thanks to Dave for his help.

if(description)
{
 script_id(11608);
 script_bugtraq_id(7510);
 script_cve_id("CVE-2003-0217");
 script_version ("$Revision: 1.10 $");

 
 name["english"] = "Neoteris IVE XSS";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the Neoteris IVE.

There is a cross site scripting issue in this
server (in the CGI swsrv.cgi) which may allow
an attacker to perform a session hijacking.


Solution : Upgrade to version 3.1 or Neoteris IVE
Risk factor : Medium";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for a XSS is Neoteris IVE";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

foreach d (make_list( "/dana/fb/smb", cgi_dirs()))
{
 req = http_get(item:string(d, "/swsrv.cgi?wg=<script>foo</script>"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( res == NULL ) exit(0);
 if( egrep(pattern:"<script>foo</script>", string:res) ){
 	security_warning(port);
	exit(0);
 }
}
