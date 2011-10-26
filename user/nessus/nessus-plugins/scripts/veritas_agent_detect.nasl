#
# (C) Tenable Network Security
#

if(description)
{
 script_id(20175);
 script_version("$Revision: 1.2 $");
 name["english"] = "VERITAS Backup Agent";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A backup agent is running on the remote host.

Description :

The remote host is running a Backup Agent that uses the Network
Data Management Protocol (NDMP).
The fact this agent is listenning on port 10000 may indicate it
is Veritas Backup Exec or Veritas NetBackup.

Risk factor :

None";

 script_description(english:desc["english"]);
 
 summary["english"] = "Detects VERITAS Backup Agent";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Service detection";
 script_family(english:family["english"]);
 
 script_require_ports(10000);
 exit(0);
}

include ("misc_func.inc");
include ("byte_func.inc");

port = 10000;

if (!get_port_state(port))
  exit (0);

soc = open_sock_tcp (port);
if (!soc) exit (0);

buf = recv (socket:soc, length:40, min:40);

if ((strlen(buf) == 40) && (getdword (blob:buf, pos:0) == 0x80000024))
{
 security_note (port);
 register_service (port:port, proto:"veritas-backup-agent");
}