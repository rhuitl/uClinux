#
# (C) Tenable Network Security
#

 desc["english"] = "
Synopsis :

It is possible to obtain information about the remote operating
system.

Description :

It is possible to get the remote operating system name and
version (Windows and/or Samba) by sending an authentication
request to port 139 or 445.

Risk factor :

None";


if(description)
{
 script_id(10785);
 script_version ("$Revision: 1.27 $");
 name["english"] = "SMB NativeLanMan";
 
 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Extracts the remote native lan manager name";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl");
 script_require_ports(139,445);
 exit(0);
}

include ("smb_func.inc");

port = kb_smb_transport();

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

name	= kb_smb_name();
session_init(socket:soc, hostname:name);

r = NetUseAdd(share:"IPC$");
if (r == 1)
  NetUseDel();

if (!isnull(Session[17]))
{
  report = string(
		"The remote Operating System is : ", Session[17],
		"\nThe remote native lan manager is : ", Session[18],
		"\nThe remote SMB Domain Name is : ", Session[19], "\n"
		);
  
  if (!get_kb_item("SMB/workgroup") && Session[19] )
  {
   set_kb_item (name:"SMB/workgroup", value:Session[19]);
  }

  if ( Session[18] )
   set_kb_item(name:"SMB/NativeLanManager", value:Session[18]);

  os = Session[17];
  if ("Windows NT" >< os)
    os = "Windows 4.0";
  else if ("Windows Server 2003" >< os)
    os = "Windows 5.2";

 if ( os ) 
  set_kb_item(name:"Host/OS/smb", value:os);

  report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		report);

  security_note(port:port, data:report);
}
