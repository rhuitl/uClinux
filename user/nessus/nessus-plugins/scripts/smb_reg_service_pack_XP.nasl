#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
# Modified by David Maciejak <david dot maciejak at kyxar dot fr> to add check for Service Pack 2
#
# See the Nessus Scripts License for details
#


 desc["english"] = "
Synopsis :

The remote system has the latest service pack installed.

Description :

By reading the registry key HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CSDVersion
it was possible to determine the Service Pack version of the Windows XP
system.

Risk factor :

None";

 desc_warn["english"] = "
Synopsis :

The remote system is about to not be supported by Microsoft any more
(starting on Oct 10, 2006).

Description :

By reading the registry key HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CSDVersion
it was possible to determine that the remote Windows XP system is not
up to date.

Supported Windows service pack levels can be found on the Microsoft web
site:

 http://support.microsoft.com/gp/lifesupsps#Windows

Solution :

Apply Windows XP Service Pack 2.

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


 desc_hole["english"] = "
Synopsis :

The remote system is not supported by Microsoft any more.

Description :

By reading the registry key HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CSDVersion
it was possible to determine that the remote Windows XP system is not
up to date.

Supported Windows service pack levels can be found on the Microsoft web
site:

 http://support.microsoft.com/gp/lifesupsps#Windows

Solution :

Apply Windows XP Service Pack 2.

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if(description)
{
 script_id(11119);
 script_bugtraq_id(10897, 11202);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-1999-0662");
 
 name["english"] = "SMB Registry : XP Service Pack version";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
This script reads the registry key HKLM\SOFTWARE\Microsoft\Windows NT\CSDVersion
to determine the Service Pack the host is running.

Sensitive servers should always run the latest service pack for security reasons.
Risk factor : High 
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the remote SP";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Alert4Web.com");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_reg_service_pack.nasl");
 script_require_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}

if ( get_kb_item("SMB/RegOverSSH") ) exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 139;

win = get_kb_item("SMB/WindowsVersion"); 
if (!win) exit(0);

sp = get_kb_item("SMB/CSDVersion");

if(win == "5.1")
{
 if (sp)
   set_kb_item(name:"SMB/WinXP/ServicePack", value:sp);
 else
 {
  report = string (desc_hole["english"],
		"\n\nPlugin output :\n\n",
		"The remote Windows XP system has no service pack applied.\n");

  security_hole(data:report, port:port);
  exit(0);
 }

 if (sp == "Service Pack 2")
 {
  report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		"The remote Windows XP system has ", sp , " applied.\n");

  security_note(data:report, port:port);
  exit(0);
 }
 
 if(sp == "Service Pack 1")
 {
  report = string (desc_hole["english"],
		"\n\nPlugin output :\n\n",
		"The remote Windows XP system has ", sp, " applied.\n",		
		"Apply SP2 to be up-to-date.\n");

  security_hole(data:report, port:port);
  exit(0);
 }
}
