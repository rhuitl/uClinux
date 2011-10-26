#
# (C) Tenable Network Security
#

if(description)
{
 script_id(20003);
 script_version("$Revision: 1.7 $");
 script_bugtraq_id(15063);
 script_cve_id("CVE-2005-2128");
 if ( defined_func("script_xref") ) script_xref(name:"IAVA", value:"2005-A-0029");

 name["english"] = "Vulnerability in DirectShow Could Allow Remote Code Execution (904706)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A vulnerability in DirectShow could allow remote code execution.

Description :

The remote host contains a version of DirectX which is vulnerable
to a remote code execution flaw.

To exploit this flaw, an attacker would need to send a specially
malformed .avi file to a user on the remote host and have him
open it.


Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-050.mspx

Risk factor :

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 904706";

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

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) <= 0 ) exit(0);
dvers = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/DirectX/Version");
if ( !dvers ) exit(0);


if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"quartz.dll", version:"6.4.3790.399", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"quartz.dll", version:"6.5.3790.2519", min_version:"6.5.3790.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"quartz.dll", version:"6.4.2600.1738", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"quartz.dll", version:"6.5.2600.2749", min_version:"6.5.2600.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"quartz.dll", version:"6.1.9.732", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"quartz.dll", version:"6.3.1.889", min_version:"6.3.0.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", file:"quartz.dll", version:"6.5.1.907", min_version:"6.5.1.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", file:"quartz.dll", version:"6.5.1.907", min_version:"6.5.1.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"quartz.dll", version:"6.5.1.907", min_version:"6.5.1.0", dir:"\system32") )
      security_hole(get_kb_item("SMB/transport"));
 hotfix_check_fversion_end(); 
}
else if ( hotfix_missing(name:"904706") > 0 ) security_hole(get_kb_item("SMB/transport"));
