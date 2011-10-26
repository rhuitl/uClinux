#
# (C) Tenable Network Security
#
if(description)
{
 script_id(20298);
 script_bugtraq_id(15826);
 script_cve_id("CVE-2005-2827");
 script_version("$Revision: 1.5 $");
 name["english"] = "Vulnerability in Windows Kernel Could Allow Elevation of Privilege (908523)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A local user can elevate his privileges on the remote host.

Description :

The remote host contains a version of the Windows kernel which is vulnerable
to a security flaw which may allow a local user to elevate his privileges
or to crash it (therefore causing a denial of service).

Solution : 

Microsoft has released a set of patches for Windows 2000:

http://www.microsoft.com/technet/security/bulletin/ms05-055.mspx

Risk factor : 

Low / CVSS Base Score : 1.6
(AV:L/AC:L/Au:NR/C:N/I:P/A:N/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote registry for 908523";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


if ( hotfix_check_sp(win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.0", file:"Ntoskrnl.exe", version:"5.0.2195.7071", dir:"\system32") )
   security_note(get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else
{
 if ( hotfix_missing(name:"908523") > 0 &&
      hotfix_missing(name:"920958") > 0 )
   security_note(get_kb_item("SMB/transport"));
}
