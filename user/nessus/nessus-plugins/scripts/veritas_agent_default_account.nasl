#
# (C) Tenable Network Security
#
#
# Credit for the default root account values:
# - Metsaploit and an anonymous contributor

if(description)
{
 script_id(19427);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2005-2611");
 script_bugtraq_id(14551);
 script_xref(name:"OSVDB", value:"18695");
 script_xref(name:"IAVA", value:"2005-t-0030");

 name["english"] = "VERITAS Backup Exec Agent Multiple Remote Vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to retrieve/delete files on the remote host. 

Description :

The remote host is running a version of VERITAS Backup Exec Agent
which is configured with a default root account. 

An attacker may exploit this flaw to retrieve files from the remote
host. 

Solution :

http://seer.support.veritas.com/docs/278434.htm

Risk factor :

High / CVSS Base Score : 9 
(AV:R/AC:L/Au:NR/C:C/A:P/I:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Test the VERITAS Backup Exec Agent Default Account";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 
 script_require_ports(10000);
 exit(0);
}


port = 10000;

#
# WebMin also listens on port 10000
#
if ( (banner = get_kb_item("www/banner/10000")) && "Server: MiniServ" >< banner ) exit(0);



connect_open_request = raw_string(
	0x80, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x01, 0x42, 0xBA, 0xF9, 0x91, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03
);


connect_client_auth_request = raw_string (
	0x80, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x01, 0x42, 0xBA, 0xF9, 0x91, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	0x00, 0x00, 0x00, 0x04, 0x72, 0x6F, 0x6F, 0x74, 0xB4, 0xB8, 0x0F, 0x26, 0x20, 0x5C, 0x42, 0x34,
	0x03, 0xFC, 0xAE, 0xEE, 0x8F, 0x91, 0x3D, 0x6F);

connect_client_auth_reply = raw_string (
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00);

if (!get_port_state(port))
  exit (0);

soc = open_sock_tcp (port);
if (!soc) exit (0);

buf = recv (socket:soc, length:40);
send (socket:soc, data:connect_open_request);
buf = recv (socket:soc, length:32);
send (socket:soc, data:connect_client_auth_request);
buf = recv (socket:soc, length:32);
if (strlen(buf) != 32)
  exit(0);
rep = substr (buf, 12, 31);

if (connect_client_auth_reply >< rep)
  security_hole(port);
