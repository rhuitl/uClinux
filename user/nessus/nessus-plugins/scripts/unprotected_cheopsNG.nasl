#
# This script was written by Michel Arboi <mikhail@nessus.org>
# GPL...
#

if(description)
{
 script_id(20161);
 script_version ("$Revision: 1.2 $");
 script_name(english:"Cheops NG without password");
 
 desc = "
Synopsis :

The remote service does not require a password for access. 

Description :

The Cheops NG agent on the remote host is running without
authentication.  Anyone can connect to this service and use it to map
your network, port scan machines and identify running services. 

Solution:

Restrict access to this port or enable authentication by starting the
agent using the '-p' option. 

Risk factor :

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:C)";

 script_description(english:desc);
 script_summary(english: "Cheops NG agent is running without authentication");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi");
 script_family(english:"Misc.");
 script_dependencie("cheopsNG_detect.nasl");
 script_require_keys("cheopsNG/unprotected");
 exit(0);
}

port = get_kb_item("cheopsNG/unprotected");
if (port) security_warning(port);
