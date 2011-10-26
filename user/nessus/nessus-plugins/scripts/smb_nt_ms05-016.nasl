#
# (C) Tenable Network Security
#
if(description)
{
 script_id(18020);
 script_bugtraq_id(13132);
 script_cve_id("CVE-2005-0063");
 if ( defined_func("script_xref") ) script_xref(name:"IAVA", value:"2005-A-0009");

 script_version("$Revision: 1.10 $");
 name["english"] = "Vulnerability in Windows Shell (893086)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the web client.

Description :

The remote version of Windows contains a flaw in the Windows Shell which
may allow an attacker to elevate his privileges and/or execute arbitrary
code on the remote host.

To exploit this flaw, an attacker would need to lure a victim into visiting
a malicious website or into opening a malicious file attachment.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-016.mspx

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if hotfix 893086 has been installed";

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

if ( hotfix_check_sp(win2k:5, xp:3, win2003:1) <= 0 ) exit(0);


if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Shell32.dll", version:"6.0.3790.280", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Shell32.dll", version:"6.0.2800.1643", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Shell32.dll", version:"6.0.2900.2620", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Shell32.dll", version:"5.0.3900.7032", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else
{
 if ( hotfix_missing(name:"893086") > 0  &&
      hotfix_missing(name:"908531") > 0  &&
      hotfix_missing(name:"921398") > 0  &&
      hotfix_missing(name:"900725") > 0 )
   security_hole(get_kb_item("SMB/transport"));
}
