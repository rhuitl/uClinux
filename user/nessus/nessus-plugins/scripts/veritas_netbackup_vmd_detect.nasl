#
#
# This script is (C) Tenable Network Security
#
#
# Only works if the remote vmd can resolve hostname and allow anoymous
# connections
#

 desc["english"] = "
Synopsis :

A backup software is running on the remote port.

Description :

The remote host is running the Veritas NetBackup Volume Manager
service.

Risk factor : 

None";

if (description)
{
 script_id(20181);
 script_version ("$Revision: 1.2 $");
 script_name(english:"Veritas NetBackup Volume Manager detection");
 script_description(english:desc["english"]);
 script_summary(english:"Determine if a remote host is running Veritas NetBackup Volume Manager Service");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_require_ports (13701, "Services/unknown");
 exit(0);
}

include ("global_settings.inc");
include ("misc_func.inc");
include ("byte_func.inc");


function check (socket, port)
{
 local_var data, line;

 data = '661292220 9 1 1\n';
 send (socket:socket, data:data);

 len = recv (socket:soc, length:4, min:4);
 if (strlen(len) != 4)
   exit (0);

 len = getdword (blob:len, pos:0);
 if ( (len <= 0) || (len >= 65535) )
   exit (0);

 buf = recv (socket:soc, length:len, min:len);
 if (strlen(buf) != len)
   exit (0);

 if (egrep (pattern:"^REQUEST ACKNOWLEDGED", string:buf))
 {
  security_note (port);
  set_kb_item (name:"VERITAS/NetBackupVolumeManager", value:port);
  register_service (port:port, proto:"vmd");
 }
}


port = 13701;
if (get_port_state(port))
{
 soc = open_sock_tcp (port);
 if (soc)
   check (socket:soc, port:port);
}

if (thorough_tests)
{
 port = get_unknown_svc();
 if (port == 13701 || ! port ) exit (0);

 if (get_port_state(port))
 {
  soc = open_sock_tcp (port);
  if (soc)
    check (socket:soc, port:port);
 }
}
