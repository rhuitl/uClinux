#
#
# This script is (C) Tenable Network Security
#
#

if (description)
{
 script_id(19387);

 script_cve_id("CVE-2005-1272");
 script_bugtraq_id(14453);
 script_xref(name:"IAVA", value:"2005-t-0028");
 script_xref(name:"OSVDB", value:"18501");

 script_version ("$Revision: 1.6 $");
 script_name(english:"BrightStor ARCserve Backup MSSQL Agent Remote Buffer Overflow Vulnerability");
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

This host is running BrightStor ARCServe MSSQL Agent.

The remote version of this software is vulnerable to a buffer
overflow vulnerability.

An attacker, by sending a specially crafted packet, may be able to
execute code on the remote host.

See also :

http://www3.ca.com/securityadvisor/vulninfo/vuln.aspx?id=33239

Solution :

Apply the patch or upgrade to a newer version when available.

Note : For ARCServe 11.1 patch QO70767 (not working) has been replaced by
       patch QO71010.

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 script_summary(english:"Check buffer overflow in BrightStor ARCServe MSSQL Agent");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain root remotely");
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_dependencies("arcserve_mssql_agent_detect.nasl");
 script_require_keys("ARCSERVE/MSSQLAgent");
 script_require_ports (6070);
 exit(0);
}

if (!get_kb_item ("ARCSERVE/MSSQLAgent")) exit (0);

port = 6070;
if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp (port);
if (!soc) exit(0);

req = "[LUHISL" + crap(data:"A", length:18) + crap (data:"B", length:669) + raw_string (0x01, 0x06) + crap (data:"C", length:0x106) + crap (data:"D", length:0x106);

send (socket:soc, data:req);
buf = recv(socket:soc, length:1000);

if (strlen(buf) > 8)
{
 val = raw_string (0x00,0x00,0x04,0x1b,0x00,0x00,0x00,0x00);

 header = substr(buf,0,7);
 if (val >< header)
   security_hole (port);
}
