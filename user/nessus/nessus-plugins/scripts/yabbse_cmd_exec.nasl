#
# (C) Renaud Deraison
#

if (description)
{
 script_id(11588);
 script_bugtraq_id(1921, 6591, 6663, 6674, 7399);
 script_cve_id("CVE-2000-1176");
 script_version ("$Revision: 1.10 $");

 script_name(english:"YaBB SE Command Execution");
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple vulnerabilities. 

Description :

The remote host is using the YaBB SE forum management system. 

According to its version number, this forum is vulnerable to a code
injection bug which may allow an attacker with a valid account to
execute arbitrary commands on this host by sending a malformed
'language' parameter in the web request. 

In addition to this flaw, this version is vulnerable to other flaws
such as SQL injection. 

See also :

http://www.ngsec.com/docs/advisories/NGSEC-2003-5.txt

Solution: 

Upgrade to YaBB SE 1.5.2 or later.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:R/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if YaBB SE can be used to execute arbitrary commands");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


if (thorough_tests) dirs = make_list("/yabbse", "/forum", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
 url = string(dir, "/index.php?board=nonexistant", rand());
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( buf == NULL ) exit(0);
 if(egrep(pattern:".*Powered by.*YaBB SE (0\.|1\.([0-4]\.|5\.[01])).*YaBB", string:buf))
   {
    security_warning(port);
    exit(0);
   }
}
