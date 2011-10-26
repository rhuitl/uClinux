#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(16271);
 script_cve_id("CVE-2005-0317", "CVE-2005-0318", "CVE-2005-0319");
 script_bugtraq_id(12395);
 script_version ("$Revision: 1.4 $");
 name["english"] = "Alt-N WebAdmin Multiple Remote Vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Alt-N WebAdmin, a web interface to MDaemon
mail server.

The remote version of this software is vulnerable to a cross site
scripting vulnerability due to a lack of filtering on user-supplied
input in the file 'useredit_account.wdm' and the file 'modalframe.wdm'.
An attacker may exploit this flaw to steal user credentials.

This software is also vulnerable to a bypass access vulnerability
in the file 'useredit_account.wdm'. An attacker may exploit this flaw
to modify user account information.

An attacker need a valid email account on the server to exploit both
vulnerabilities.

Solution : Upgrade to WebAdmin 3.0.3.
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the version of Alt-N WebAdmin";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:1000);


if(!get_port_state(port))exit(0);

function check(url)
{
req = http_get(item:string(url, "/login.wdm"), port:port);
r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
if ( r == NULL ) exit(0);
if ( egrep(pattern:'<A href="http://www\\.altn\\.com/WebAdmin/" target="_blank">WebAdmin</A> v([0-2]\\.|3\\.0\\.[0-2]).*', string:r))
 {
 security_warning(port);
 exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(url:dir);
}
