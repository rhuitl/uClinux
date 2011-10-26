#
# (C) Tenable Network Security
#
if(description)
{
 script_id(15460);
 script_bugtraq_id(10677);
 script_cve_id("CVE-2004-0214", "CVE-2004-0572");
 if ( defined_func("script_xref") ) script_xref(name:"IAVA", value:"2004-A-0019");


 script_version("$Revision: 1.8 $");
 name["english"] = "Vulnerability in Windows Shell (841356)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the web client.

Description :

The remote version of Windows contains a flaw in the Windows Shell which
may allow an attacker to execute arbitrary code on the remote host.

To exploit this flaw, an attacker would need to lure a victim into visiting
a malicious website or into opening a malicious file attachment.

Solution : 

Microsoft has released a set of patches for Windows NT, 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms04-037.mspx

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if hotfix 841356 has been installed";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
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

if ( hotfix_check_sp(nt:7, win2k:5, xp:2, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Shell32.dll", version:"6.0.3790.205", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Shell32.dll", version:"6.0.2800.1580", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Shell32.dll", version:"6.0.2750.166", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Shell32.dll", version:"5.0.3900.6975", dir:"\system32") || 
      hotfix_is_vulnerable (os:"4.0", file:"Shell32.dll", version:"4.72.3843.3100", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"841356") > 0  )
	security_hole(get_kb_item("SMB/transport"));

