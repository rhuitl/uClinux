#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Broken link deleted
#
# GPL
#

if(description)
{
  script_id(10921);
  script_version ("$Revision: 1.9 $");
 
  script_name(english:"RemotelyAnywhere SSH detection");
 
  desc["english"] = "
The RemotelyAnywhere SSH server is running on this system.
According to NAVCIRT crackers love this management tool.

If you installed it, ignore this warning. If not, your machine is 
compromised by an attacker.

Risk factor : None / High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect RemotelyAnywhere SSH server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
  family["english"] = "Backdoors";
  script_family(english:family["english"]);
  script_dependencie("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22); 
  exit(0);
}

port = get_kb_item("Services/ssh");
if (! port) port = 22;

if(!get_port_state(port))exit(0);


banner = get_kb_item("SSH/banner/" + port);
if (! banner) exit(0);

if (ereg(pattern:'SSH-[0-9.-]+[ \t]+RemotelyAnywhere', string:banner))
{
  security_note(port);
}

# TBD: check default account administrator / remotelyanywhere
