#
#
# This script is (C) Tenable Network Security
#
#

if (description)
{
 script_id(18041);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0013");
 script_bugtraq_id(13102);
 script_cve_id("CVE-2005-1018");
 script_version ("$Revision: 1.6 $");
 script_name(english:"BrightStor ARCserve Backup UniversalAgent Remote Buffer Overflow Vulnerability");
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

This host is running BrightStor ARCServe UniversalAgent.

The remote version of this software is vulnerable to a buffer
overflow vulnerability.

An attacker, by sending a specially crafted packet, may be able to
execute code on the remote host.

See also :

http://www.securityfocus.com/archive/1/395512

Solution :

Upgrade to the newest version of this software, when available

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 script_summary(english:"Check buffer overflow in BrightStor ARCServe UniversalAgent");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain root remotely");
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_dependencies("arcserve_universalagent_detect.nasl");
 script_require_keys("ARCSERVE/UniversalAgent");
 script_require_ports (6050);
 exit(0);
}

if (!get_kb_item ("ARCSERVE/UniversalAgent")) exit (0);

port = 6050;
if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp (port);
if (!soc) exit(0);

data = raw_string (0x00,0x00,0x00,0x00,0x03,0x20,0xBC,0x02);
data += crap (data:"2", length:256);
data += crap (data:"A", length:32);
data += raw_string (0x0B, 0x11, 0x0B, 0x0F, 0x03, 0x0E, 0x09, 0x0B,
                    0x16, 0x11, 0x14, 0x10, 0x11, 0x04, 0x03, 0x1C,
                    0x11, 0x1C, 0x15, 0x01, 0x00, 0x06);
data += crap (data:"A", length:390);

send (socket:soc, data:data);
ret = recv (socket:soc, length:4096);

if ((strlen(ret) == 8) && (hexstr(ret) >< "0000730232320000"))
{
 security_hole (port);
}
