#
# (C) Tenable Network Security
#
if(description)
{
 script_id(16124);
 script_version("$Revision: 1.10 $");
 script_bugtraq_id(12233);
 script_cve_id("CVE-2004-1305", "CVE-2004-1049");
 if ( defined_func("script_xref") ) script_xref(name:"IAVA", value:"2005-A-0001");

 name["english"] = "Cursor and Icon Format Handling Code Execution (891711) (registry check)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the web or email
client.

Description :

The remote host contains a version of the Windows kernel which is vulnerable
to a security flaw in the way that cursors and icons are handled. An attacker
may be able to execute arbitrary code on the remote host by constructing a
malicious web page and entice a victim to visit this web page. An attacker may
send a malicious email to the victim to exploit this flaw too.

Solution : 

Microsoft has released a set of patches for Windows NT, 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-002.mspx

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote registry for MS05-002";

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


if ( hotfix_check_sp(nt:7, xp:2, win2k:5, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"User32.dll", version:"5.2.3790.245", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"User32.dll", version:"5.1.2600.1617", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"User32.dll", version:"5.0.2195.7017", dir:"\system32") || 
      hotfix_is_vulnerable (os:"4.0", file:"User32.dll", version:"4.0.1381.7342", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"User32.dll", version:"4.0.1381.33630", min_version:"4.0.1381.33000", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else
{
 if ( hotfix_missing(name:"891711") > 0 )
	{
	# Superseeded by MS05-18
	if ( hotfix_check_sp(win2k:5, win2003:1, xp:2) > 0 && hotfix_missing(name:"890859") <= 0 ) exit(0);
	# Superseeded by MS05-053
         if ( hotfix_check_sp(xp:2) > 0 && hotfix_missing(name:"896424") <= 0  ) exit(0);
	security_hole(get_kb_item("SMB/transport"));
	}
}
