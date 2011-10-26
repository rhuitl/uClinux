#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: Marc Ruef <marc.ruef@computec.ch>
#
# This script is released under the GNU GPLv2
#

if(description)
{
  script_id(14824);
  script_cve_id("CVE-2004-1699");
  script_bugtraq_id(11232);
  script_version("$Revision: 1.4 $");
  script_name(english:"Pinnacle ShowCenter Skin DoS");

 
 desc["english"] = "
The remote host runs the Pinnacle ShowCenter web based interface.

The remote version of this software is vulnerable to a remote denial of 
service due to a lack of sanity checks on skin parameter.

With a specially crafted URL, an attacker can deny service of the ShowCenter 
web based interface.

Solution: Upgrade to the newest version of this software.
Risk factor : Medium";

  script_description(english:desc["english"]);

  script_summary(english:"Checks skin DoS in Pinnacle ShowCenter");
  script_category(ACT_DENIAL);
  
  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 8000);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8000);
if ( ! port ) exit(0);

if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc)
 {
  buf = http_get(item:"/ShowCenter/SettingsBase.php?Skin=ATKnessus", port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  #try to detect errors
  if(egrep(pattern:"Fatal error.*loaduserprofile.*Failed opening required", string:r))
  {
    security_warning(port);
  }
  http_close_socket(soc); 
 }
}
exit(0);
