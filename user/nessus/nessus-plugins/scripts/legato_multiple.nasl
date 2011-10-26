#
# (C) Tenable Network Security
#

if(description)
{
 script_id(19558);
 script_version("$Revision: 1.4 $");
 script_bugtraq_id(14582);
 script_cve_id("CVE-2005-0357", "CVE-2005-0358", "CVE-2005-0359");

 name["english"] = "EMC Legato Networker Multiple Vulnerabilities";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

The remote host is running one of the following product :

 - Legato Networker
 - Sun StorEdge Enterprise Backup Software
 - Sun Solstice Backup Software

The remote version of this software is vulnerable to denial of service,
unauthorized access and remote command execution vulnerabilities.

Solution :

http://www.legato.com/support/websupport/product_alerts/081605_NW-7x.htm
http://sunsolve.sun.com/search/document.do?assetkey=1-26-101886-1

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if Legato Networker is vulnerable";

 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencies ("legato_detect.nasl");
 script_require_keys ("LegatoNetworker/installed");
 script_require_ports(7938);
 exit(0);
}

if (! get_kb_item("LegatoNetworker/installed") )
  exit (0);

port = 7938;
soc = open_sock_tcp (port);
if (!soc) exit(0);

rpc_port1 = rand() % 256;
rpc_port2 = rand() % 256;

xid1 = rand() % 256;
xid2 = rand() % 256;
xid3 = rand() % 256;
xid4 = rand() % 256;

pack = 
raw_string(	0x80, 0, 0, 0x38,	# Last fragment; fragment length = 40
		xid1, xid2, xid3, xid4,	# XID
		0, 0, 0, 0,		# Call
		0, 0, 0, 2,		# RPC version = 2
		0, 1, 0x86, 0xA0,	# Programm = portmapper (10000)
		0, 0, 0, 2,		# Program version = 2
		0, 0, 0, 1,		# Procedure = 1 (SET)
		0, 0, 0, 0, 0, 0, 0, 0,	# Null credential
		0, 0, 0, 0, 0, 0, 0, 0,	# Null verifier
		0, 0x54, 0x4E, 0x53,	# Program
		0, 0, 0, 1,		# Version = 1
		0, 0, 0, 6,		# Protocol = TCP
		0, 0, rpc_port1, rpc_port2	# Port
	);

send(socket: soc, data: pack);
r = recv(socket: soc, length: 32);

if ((strlen(r) != 32) || (ord(r[0]) != 0x80))
  exit (0);

reply = substr(r, 28, 31);

if ("0000001" >!< hexstr(reply))
  exit (0);

xid1 = rand() % 256;
xid2 = rand() % 256;
xid3 = rand() % 256;
xid4 = rand() % 256;

pack = 
raw_string(	0x80, 0, 0, 0x38,	# Last fragment; fragment length = 40
		xid1, xid2, xid3, xid4,	# XID
		0, 0, 0, 0,		# Call
		0, 0, 0, 2,		# RPC version = 2
		0, 1, 0x86, 0xA0,	# Programm = portmapper (10000)
		0, 0, 0, 2,		# Program version = 2
		0, 0, 0, 2,		# Procedure = 2 (UNSET)
		0, 0, 0, 0, 0, 0, 0, 0,	# Null credential
		0, 0, 0, 0, 0, 0, 0, 0,	# Null verifier
		0, 0x54, 0x4E, 0x53,	# Program
		0, 0, 0, 1,		# Version = 1
		0, 0, 0, 6,		# Protocol = TCP
		0, 0, rpc_port1, rpc_port2	# Port	
	);

send(socket: soc, data: pack);
r = recv(socket: soc, length: 32);

if ((strlen(r) != 32) || (ord(r[0]) != 0x80))
  exit (0);

reply = substr(r, 28, 31);
if ("00000001" >< hexstr(reply))
  security_hole (port);
