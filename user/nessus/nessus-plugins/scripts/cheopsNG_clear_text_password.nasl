#
# This script was written by Michel Arboi <mikhail@nessus.org>
# GPL...
#

if(description)
{
 script_id(20162);
 script_version ("$Revision: 1.2 $");
 script_name(english: "Cheops NG clear text authentication");
 
 desc = "
Synopsis :

A Cheops NG agent is running on the remote host.

Description :

Cheops NG is running on this port.
Users with a valid account on this machine can connect 
to this service and use it to map your network, port scan 
machines and identify running services.

Passwords are transmitted in clear text and could be sniffed.
More, using this Cheops agent, it is possible to brute force
login/passwords on this system.

Solution:

Configure Cheops to run on top of SSL or block this port 
from outside communication if you want to further restrict 
the use of Cheops.

Risk factor :

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:H/Au:NR/C:P/A:N/I:P/B:C)";

 script_description(english:desc);
 script_summary(english: "Cheops NG agent uses clear text passwords");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi");
 script_family(english: "Service detection");
 script_dependencie("cheopsNG_detect.nasl");
 script_require_keys("cheopsNG/password");
 exit(0);
}

port = get_kb_item("cheopsNG/password");
if (port && get_port_transport(port) == ENCAPS_IP ) security_warning(port);
