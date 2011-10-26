#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15970);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-b-0016");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0039");
 script_bugtraq_id(11763, 11922);
 script_cve_id("CVE-2004-0567", "CVE-2004-1080");
 name["english"] = "WINS Code Execution (870763) (network check)";

 script_version("$Revision: 1.6 $");
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

The remote Windows Internet Naming Service (WINS) is vulnerable to a 
flaw which could allow an attacker to execute arbitrary code on this host.

To exploit this flaw, an attacker needs to send a specially crafted
packet on port 42 of the remote host.

Solution :

http://www.microsoft.com/technet/security/bulletin/ms04-045.mspx

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if hotfix 870763 has been installed";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);

 script_dependencies("netbios_name_get.nasl");
 script_require_ports(42);
 exit(0);
}


port = 42;
if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

request = raw_string (0x00,0x00,0x00,0x29,0x00,0x00,0x78,0x00,0x00,0x00,0x00,0x00,
		      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x02,0x00,0x05,
	    	      0x00,0x00,0x00,0x00,0x60,0x56,0x02,0x01,0x00,0x1F,0x6E,0x03,
	    	      0x00,0x1F,0x6E,0x03,0x08,0xFE,0x66,0x03,0x00);

send(socket:soc, data:request);

r = recv(socket:soc, length:4096);
if (!r) exit (0);

if (strlen(r) < 20) exit (0);

if (ord(r[6]) != 0x78) exit (0);

pointer = substr(r,16,19);

request = raw_string (0x00,0x00,0x00,0x0F,0x00,0x00,0x78,0x00) + pointer + raw_string(
		      0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x00);

send(socket:soc, data:request);

r = recv(socket:soc, length:4096);
if (!r) exit (0);

if (strlen(r) < 8) exit (0);

if (ord(r[6]) == 0x78)
  security_hole (port);
