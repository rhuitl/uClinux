#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15912);
 script_version("$Revision: 1.5 $");
 script_bugtraq_id(9624);
 script_cve_id("CVE-2003-0825");

 script_version("$Revision: 1.5 $");
 name["english"] = "WINS Buffer Overflow (830352 - netbios check)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

The remote Windows Internet Naming Service (WINS) is vulnerable to a 
flaw which could allow an attacker to execute arbitrary code on this host.

To exploit this flaw, an attacker would need to send a specially crafted
packet with improperly advertised lengths.

Solution :

http://www.microsoft.com/technet/security/bulletin/MS04-006.mspx

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if hotfix 830352 has been installed (Netbios)";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);

 script_dependencies("netbios_name_get.nasl");
 script_require_ports(137);
 exit(0);
}

if ( get_kb_item("SMB/samba") ) exit(0);

port = 137;
soc = open_sock_udp(port);
if ( ! soc ) exit(0);


request = raw_string (0x83, 0x98, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		      0x3E, 0x46, 0x45, 0x45, 0x46, 0x45, 0x4f, 0x45, 0x42, 0x45, 0x43, 0x45,
                      0x4d, 0x45, 0x46 ) + crap (data:"A", length:48) +
		      crap (data:raw_string(0x3F), length:192) + 
		      raw_string (0x22) + crap (data:raw_string (0x3F), length:34) + 
                      raw_string ( 0x00, 0x00, 0x20, 0x00, 0x01); 

send(socket:soc, data:request);

r = recv(socket:soc, length:4096);
if (!r) exit (0);

r = substr (r, 13, 17);

if ("FEEFE" >< r)
  security_hole (port);

