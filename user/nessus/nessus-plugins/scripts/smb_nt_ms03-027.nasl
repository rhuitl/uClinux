#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11792);
 script_version("$Revision: 1.18 $");
 script_cve_id("CVE-2003-0306");
 
 name["english"] = "Buffer overrun in Windows Shell (821557)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through Explorer.

Description :

The remote host is running a version of Windows which has a flaw in 
its shell. An attacker could exploit it by creating a malicious Desktop.ini
file which triggers the flaw, and put it on a shared folder and wait
for someone to browse it.

Solution : 

Microsoft has released a set of patches for Windows XP :

http://www.microsoft.com/technet/security/bulletin/ms03-027.mspx

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix Q823980";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_sp(xp:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Shell32.dll", version:"6.0.2800.1233", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Shell32.dll", version:"6.0.2800.115", dir:"\system32") )
   security_warning (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"839645") > 0 &&
     hotfix_missing(name:"821157") > 0 &&
     hotfix_missing(name:"841356") > 0 )
	security_warning(get_kb_item("SMB/transport"));

