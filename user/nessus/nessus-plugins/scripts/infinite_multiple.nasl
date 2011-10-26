#
# This script was written by Tenable Network Security
#

if(description)
{
 script_id(16278);
 script_cve_id("CVE-2005-0323", "CVE-2005-0324");
 script_bugtraq_id(12399); 
 script_version ("$Revision: 1.3 $");

 name["english"] = "Infinite Mobile Delivery Webmail Multiple vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
There are flaws in the remote Infinite Mobile Delivery, a web interface
to provide wireless access to mail.

This version of Infinite Mobile Delivery is vulnerable to a cross site
scripting vulnerability and to a path disclosure vulnerability.
An attacker, exploiting this flaw, would be able to steal user credentials
or use disclosed information to launch further attacks.

Solution: None at this time

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of Infinite Mobile Delivery";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "httpver.nasl", "http_version.nasl");
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

function check(loc)
{
 req = http_get(item:string(loc, "/"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if ( egrep(pattern:"^Powered by .*Infinite Mobile Delivery v([0-1]\..*|2\.[0-6]).* -- &copy; Copyright [0-9]+-[0-9]+ by .*Captaris", string:r))
 {
   security_warning(port);
   exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

