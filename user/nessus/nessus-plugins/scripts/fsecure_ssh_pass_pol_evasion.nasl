#
# (C) Tenable Network Security
#

if(description)
{
  script_id(12099);
  script_bugtraq_id(9824);
  script_version ("$Revision: 1.4 $");

  name["english"] = "F-Secure SSH Password Authentication Policy Evasion";
  script_name(english:name["english"]);

  desc["english"] = "
The remote host is running F-Secure SSH. 

This version contains a bug which may allow a user to log in
using a password even though the server policy disallows it. 

An attacker may exploit this flaw to set up a dictionary attack against the
remote SSH server and eventually get access to this host.

Solution : Upgrade to F-Secure SSH 3.1.0 build 9 or newer
Risk factor : Low";

  script_description(english:desc["english"]);

  summary["english"] = "F-Secure SSH version";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO); 
  script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
  script_family(english:"Gain a shell remotely");
  script_require_ports("Services/ssh", 22);
  script_dependencie("ssh_detect.nasl");

  exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/ssh");
if (!port) port = 22;

banner = get_kb_item( "SSH/banner/" + port );
if(!banner) exit(0);

#
# SSH-2.0-3.2.0 F-Secure SSH Windows NT Server
# versions up to 3.1.0 affected
#
if(ereg(pattern:"^SSH-2.0-([12]\..*|3\.[01]\..*) F-Secure SSH", string:banner, icase:TRUE))
{ 
  security_warning(port);
}
