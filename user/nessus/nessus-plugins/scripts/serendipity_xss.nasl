#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: Stefan Esser
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(15914);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2004-2525");
 script_bugtraq_id(11790);
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"12177");

 name["english"] = "Serendipity XSS Flaw";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by a
cross-site scripting flaw. 

Description :

The remote version of Serendipity is vulnerable to cross-site
scripting attacks due to a lack of sanity checks on the 'searchTerm'
parameter in the 'compat.php' script.  With a specially crafted URL,
an attacker can cause arbitrary code execution in a user's browser
resulting in a loss of integrity. 

See also : 

http://www.nessus.org/u?e47198ec
http://www.s9y.org/5.html

Solution : 

Upgrade to Serendipity 0.7.1 or newer.

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Serendipity XSS flaw";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("serendipity_detect.nasl", "cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
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
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/serendipity"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 loc = matches[2];

 req = http_get(item:string(loc, "/index.php?serendipity%5Baction%5D=search&serendipity%5BsearchTerm%5D=%3Cscript%3Efoo%3C%2Fscript%3E"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if ( "<script>foo</script>" >< r)
  security_note(port);
}
