#
# (C) Tenable Network Security
#

if(description)
{
 script_id(19557);
 script_version("$Revision: 1.2 $");

 name["english"] = "EMC Legato Networker detection";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A backup software is running on this port.

Description :

The remote host is running EMC Legato Networker backup software or one
of these derivates :

 - Sun StorEdge Enterprise Backup Software
 - Sun Solstice Backup Software


Solution :

If this service is not needed, disable it or filter incoming traffic
to this port.

Risk factor : 

None";

 script_description(english:desc["english"]);
 
 summary["english"] = "Detect if Legato Networker Service are installed";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Service detection";
 script_family(english:family["english"]);
 script_require_ports(7938);
 exit(0);
}

port = 7938;
soc = open_sock_tcp (port);
if (!soc) exit(0);

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
		0, 0, 0, 3,		# Procedure = 3 (GETPORT)
		0, 0, 0, 0, 0, 0, 0, 0,	# Null credential
		0, 0, 0, 0, 0, 0, 0, 0,	# Null verifier
		0, 5, 0xf3, 0xe1,	# Program = 390113 (nsrexec ?)
		0, 0, 0, 1,		# Version = 1
		0, 0, 0, 6,		# Protocol = TCP
		0, 0, 0, 0		# Port
	);

send(socket: soc, data: pack);
r = recv(socket: soc, length: 32);

if ((strlen(r) != 32) || (ord(r[0]) != 0x80) || (ord(r[3]) != 0x1C))
  exit (0);

reply = substr(r, 28, 31);

if ("0000000" >!< hexstr(reply))
{
  set_kb_item (name:"LegatoNetworker/installed", value:TRUE);
  security_note(port);
}
