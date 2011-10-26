#
# (C) Tenable Network Security
#

if(description)
{
 script_id(20002);
 script_version("$Revision: 1.5 $");
 script_cve_id("CVE-2005-2122", "CVE-2005-2118", "CVE-2005-2117");
 if ( defined_func("script_xref") ) script_xref(name:"IAVA", value:"2005-A-0027");
 script_bugtraq_id(15070, 15069, 15064);

 name["english"] = "Vulnerabilities in Windows Shell Could Allow Remote Code Execution (900725)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Vulnerabilities in the Windows Shell may allow an attacker to execute
arbitrary code on the remote host.

Description :

The remote version of Windows contains a version of the Windows Shell
which has several vulnerabilities.

An attacker may exploit these vulnerabilities by :

 - Sending a malformed .lnk file a to user on the remote host which
   triggers an overflow

 - Sending a malformed HTML document to a user on the remote host and
   have him view it in the Windows Explorer preview pane


Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-049.mspx

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 900725";

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

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"shell32.dll", version:"6.0.3790.413", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"shell32.dll", version:"6.0.3790.2534", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"shell32.dll", version:"6.0.2800.1751", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"shell32.dll", version:"6.0.2900.2763", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0",       file:"shell32.dll", version:"5.0.3900.7071", dir:"\system32") )
      security_warning(get_kb_item("SMB/transport"));
 hotfix_check_fversion_end(); 
}
else if ( hotfix_missing(name:"900725") > 0 ) security_warning(get_kb_item("SMB/transport"));
