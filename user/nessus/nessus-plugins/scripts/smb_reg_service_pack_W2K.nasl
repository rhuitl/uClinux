#
# This script was written by Tenable Network Security
#
# This script is released under Tenable Plugins License
#


 desc["english"] = "
Synopsis :

Remote system has latest service pack installed.

Description :

By reading the registry key HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CSDVersion
it was possible to determine the Service Pack version of the Windows 2000
system.

Risk factor :

None";


 desc_hole["english"] = "
Synopsis :

Remote system is not up to date.

Description :

By reading the registry key HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CSDVersion
it was possible to determine that the remote Windows 2000 system is not
up to date.

Solution :

Apply Windows 2000 Service Pack 4.

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if(description)
{
 script_id(10531);
 script_bugtraq_id(7930, 8090, 8128, 8154);
 script_version ("$Revision: 1.33 $");
 script_cve_id("CVE-1999-0662");
 name["english"] = "SMB Registry : Win2k Service Pack version";
 
 script_name(english:name["english"]);
 

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the remote SP";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_reg_service_pack.nasl");
 script_require_keys("SMB/WindowsVersion","SMB/CSDVersion");
 exit(0);
}

port = get_kb_item("SMB/transport");
if(!port)port = 139;

win = get_kb_item("SMB/WindowsVersion"); 
if (!win) exit(0);

sp = get_kb_item("SMB/CSDVersion");

if(win == "5.0")
{
 if (sp)
 {
  if ( ("Service Pack 4" >< sp) && (get_kb_item("SMB/URP1")) )
  {
    replace_kb_item (name:"SMB/CSDVersion", value:"Service Pack 5");
    set_kb_item(name:"SMB/Win2K/ServicePack", value:"Service Pack 5");
  }
  else
    set_kb_item(name:"SMB/Win2K/ServicePack", value:sp);
 }


 if((!sp) || (ereg(pattern:"Service Pack [123]",string:sp)))
 {
  report = 'The remote Windows 2000 does not have the Service Pack 4 applied.\n';
  if (!sp)
    report = string (desc_hole["english"],
		"\n\nPlugin output :\n\n",
		"The remote Windows 2000 system has no service pack applied.\n");
  else
  report = string (desc_hole["english"],
		"\n\nPlugin output :\n\n",
		"The remote Windows 2000 system has ", sp , " applied.\n");

  security_warning(data:report, port:port);
  exit(0);
 }
 else
 {
  report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		"The remote Windows 2000 system has ", sp , " applied.\n");

  security_note (port:port, data:report);
 }
}
