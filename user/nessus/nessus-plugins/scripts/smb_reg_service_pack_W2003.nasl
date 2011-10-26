#
# (C) Tenable Network Security
#

 desc["english"] = "
Synopsis :

Remote system has latest service pack installed.

Description :

By reading the registry key HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CSDVersion
it was possible to determine the Service Pack version of the Windows 2003
system.

Risk factor :

None";


 desc_hole["english"] = "
Synopsis :

Remote system is not up to date.

Description :

By reading the registry key HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CSDVersion
it was possible to determine that the remote Windows 2003 system is not
up to date.

Solution :

Apply Windows 2003 Service Pack 1.

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if(description)
{
 script_id(17662);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-1999-0662");
 script_bugtraq_id(12969, 12972, 13008);
 
 name["english"] = "SMB Registry : Windows 2003 Server SP1";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Windows 2003 Server but does not have Service
Pack 1 applied.

Solution : Install Windows 2003 SP1
See also : http://www.microsoft.com/windowsserver2003/default.mspx
Risk Factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the remote SP";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_reg_service_pack.nasl");
 script_require_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}

port = get_kb_item("SMB/transport");
if(!port)port = 139;

win = get_kb_item("SMB/WindowsVersion"); 
if (!win) exit(0);

sp = get_kb_item("SMB/CSDVersion");

if(win == "5.2" )
{
 if ( ! sp ) 
 {
  report = string (desc_hole["english"],
		"\n\nPlugin output :\n\n",
		"The remote Windows 2003 system has no service pack applied.\n");

  security_warning(data:report, port:port);
  exit(0);
 }
 else
 {
  set_kb_item(name:"SMB/Win2003/ServicePack", value:sp);

  report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		"The remote Windows 2003 system has ",sp," applied.\n");

  security_note(data:report, port:port);
  exit(0);
 }
}
