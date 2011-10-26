#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16327);
 script_version("$Revision: 1.8 $");
 script_cve_id("CVE-2005-0047", "CVE-2005-0044");
 script_bugtraq_id(12488, 12483);
 if ( defined_func("script_xref") ) script_xref(name:"IAVA", value:"2005-A-0007");

 name["english"] = "Vulnerability in OLE and COM Could Allow Code Execution (873333)";

 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through explorer.

Description :

The remote host is running a version of Windows which is vulnerable to two
vulnerabilities when dealing with OLE and/or COM. 

These vulnerabilities may allow a local user to escalate his privileges
and allow a remote user to execute arbitrary code on the remote host.

To exploit these flaws, an attacker would need to send a specially crafted
document to a victim on the remote host.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/MS05-012.mspx

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for KB 873333 via the registry";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);

 script_dependencies("smb_hotfixes.nasl" );
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");

if ( hotfix_check_sp(xp:3, win2k:5, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Ole32.dll", version:"5.2.3790.250", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Ole32.dll", version:"5.1.2600.1619", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Ole32.dll", version:"5.1.2600.2595", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Ole32.dll", version:"5.0.2195.7021", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else
{
 if ( hotfix_missing(name:"873333") > 0  &&
      hotfix_missing(name:"902400") > 0 &&
      !((hotfix_check_sp (win2k:6) > 0) && ( hotfix_missing(name:"913580") <= 0 ) ) )
   security_hole(get_kb_item("SMB/transport"));
}
