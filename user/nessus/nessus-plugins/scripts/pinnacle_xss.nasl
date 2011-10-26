#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: Secunia Research
#
# This script is released under the GNU GPLv2
#

if(description)
{
  script_id(15485);
  script_cve_id("CVE-2004-1700");
  script_bugtraq_id(11415);
  script_version("$Revision: 1.8 $");
  script_name(english:"Pinnacle ShowCenter Skin XSS");

  desc["english"] = "
The remote host runs the Pinnacle ShowCenter web based interface.

The remote version  of this software is vulnerable to cross-site 
scripting attack due to a lack of sanity checks on skin parameter
in the SettingsBase.php script.

With a specially crafted URL, an attacker can cause arbitrary
code execution resulting in a loss of integrity.

Solution: Upgrade to the newest version of this software.
Risk factor : Medium";

  script_description(english:desc["english"]);

  script_summary(english:"Checks skin XSS in Pinnacle ShowCenter");
  script_category(ACT_GATHER_INFO);
  
  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
  script_family(english:"CGI abuses : XSS");
  script_dependencie("cross_site_scripting.nasl"); 
  script_require_ports("Services/www", 8000);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8000);
if ( ! port ) exit(0);
if(!can_host_php(port:port)) exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if(get_port_state(port))
{
  buf = http_get(item:"/ShowCenter/SettingsBase.php?Skin=<script>foo</script>", port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if(egrep(pattern:"<script>foo</script>", string:r))
  {
    security_warning(port);
  }
}
exit(0);
