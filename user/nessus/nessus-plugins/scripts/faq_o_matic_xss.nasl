#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: superpetz <superpetz@hushmail.com>
# This script is released under the GNU GPLv2
#

if(description)
{
  script_id(15540);
  script_bugtraq_id(4565);
  script_cve_id("CVE-2002-0230", "CVE-2002-2011");
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"8661");
  script_version("$Revision: 1.7 $");
  script_name(english:"Faq-O-Matic fom.cgi XSS");
 
 desc["english"] = "
The remote host runs Faq-O-Matic, a CGI-based system that automates 
the process of maintaining a FAQ.

The remote version of this software is vulnerable to cross-site scripting 
attacks in the script 'fom.cgi'.

With a specially crafted URL, an attacker can cause arbitrary code 
execution resulting in a loss of integrity.

Solution: Upgrade to the latest version of this software
Risk factor : Medium";

  script_description(english:desc["english"]);

  script_summary(english:"Checks Faq-O-Matic XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
  script_family(english:"CGI abuses : XSS");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("cross_site_scripting.nasl");
  exit(0);
}

# the code!

include("http_func.inc");
include("http_keepalive.inc");


function check(req)
{
  buf = http_get(item:string(req,"/fom/fom.cgi?cmd=<script>foo</script>&file=1&keywords=nessus"), port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if(egrep(pattern:"<script>foo</script>", string:r))
  {
 	security_warning(port);
	exit(0);
  }
}

port = get_http_port(default:80);
if ( ! port ) exit(0);
if(!get_port_state(port)) exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);
foreach dir (cgi_dirs()) check(req:dir);
exit(0);
