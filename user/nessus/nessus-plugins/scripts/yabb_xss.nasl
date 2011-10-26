#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: GulfTech Security <security@gulftech.org>
#
#  This script is released under the GNU GPL v2
#
# Fixes by Tenable:
#   - added CVE xrefs.

if(description)
{
 script_id(14782);
 script_cve_id("CVE-2004-2402", "CVE-2004-2403");
 script_bugtraq_id(11214, 11215);
 script_version ("$Revision: 1.9 $");
 name["english"] = "YaBB XSS and Administrator Command Execution";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a CGI application that suffers from
multiple vulnerabilities. 

Description :

The 'YaBB.pl' CGI is installed.  This version is affected by a
cross-site scripting vulnerability.  This issue is due to a failure of
the application to properly sanitize user-supplied input. 

As a result of this vulnerability, it is possible for a remote
attacker to create a malicious link containing script code that will
be executed in the browser of an unsuspecting user when followed. 

Another flaw in YaBB may allow an attacker to execute malicious
administrative commands on the remote host by sending malformed IMG
tags in posts to the remote YaBB forum and waiting for the forum
administrator to view one of the posts. 

See also : 

http://archives.neohapsis.com/archives/bugtraq/2004-09/0227.html

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:R/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks YaBB.pl XSS";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak",
		francais:"Ce script est Copyright (C) 2004 David Maciejak");
		
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);

if (!get_port_state(port))exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if (thorough_tests) dirs = make_list("/yabb", "/forum", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (cgi_dirs())
{
 req = string(dir, "/YaBB.pl?board=;action=imsend;to=%22%3E%3Cscript%3Efoo%3C/script%3E");
 req = http_get(item:req, port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if (egrep(pattern:"<script>foo</script>", string:r))
 {
       security_warning(port);
       exit(0);
 }
}
