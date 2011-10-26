#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16474);
 script_cve_id("CVE-2005-0487");
 script_bugtraq_id(12563);
 script_version("$Revision: 1.6 $");

 name["english"] = "Kayako eSupport Cross-Site Scripting Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that suffers from a cross-
site scripting flaw. 

Description :

The remote host is running Kayako eSupport, a web-based support
and help desk application.

This version of eSupport is vulnerable to a cross-site scripting flaw
involving the 'nav' parameter of the 'index.php' script.  An attacker,
exploiting this flaw, would need to be able to coerce an unsuspecting
user into visiting a malicious website.  Upon successful exploitation,
the attacker would be able to steal credentials or execute browser-side
code. 

See also :

http://marc.theaimsgroup.com/?l=full-disclosure&m=110845724029888&w=2

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of Kayako eSupport";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_family(english:"CGI abuses : XSS");
 
 script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);


function check(url)
{
 local_var req, res;
 req = http_get(item:url + "/index.php?_a=knowledgebase&_j=questiondetails&_i=2&nav=<script>alert(document.cookie)</script>", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if ( res == NULL ) exit(0);
 if ( egrep(pattern:"<script>alert(document.cookie)</script>", string:res) ) 
 {
        security_note(port);
        exit(0);
 }
}


foreach dir ( cgi_dirs() )
{
  check(url:dir);
}
