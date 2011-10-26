#
# (C) Tenable Network Security
#
if(description)
{
 script_id(14614);
 script_cve_id("CVE-2004-1640");
 script_bugtraq_id(11064);
 script_version("$Revision: 1.7 $");
 
 name["english"] = "XOOPS Dictionary Module Cross Scripting Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains PHP scripts that are affected by
cross-site scripting flaws. 

Description :

The remote version of Xoops is vulnerable to several cross-site
scripting attacks.  An attacker can exploit it using the 'terme' and
'letter' parameters of the 'search.php' and 'letter.php' scripts
respectively.  This can be used to take advantage of the trust between
a client and server allowing the malicious user to execute malicious
JavaScript on the client's machine. 

See also :

http://marc.theaimsgroup.com/?l=bugtraq&m=109394077209963&w=2

Solution : 

Unknown at this time.

Risk factor: 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an XSS bug in Xoops";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("xoops_detect.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
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
if (  get_kb_item(string("www/", port, "/generic_xss")) ) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/xoops"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 loc = matches[2];

 req = http_get(item:string(loc, "/letter.php?<script>foo</script>"), port:port);

 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if('<script>foo</script>' >< r )
 {
 	security_note(port);
	exit(0);
 }
}
