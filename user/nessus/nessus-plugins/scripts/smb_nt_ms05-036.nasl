#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18681);
 script_version("$Revision: 1.7 $");
 script_bugtraq_id(14214);
 script_cve_id("CVE-2005-1219");
 if ( defined_func("script_xref") ) script_xref(name:"IAVA", value:"2005-A-0018");

 name["english"] = "Vulnerability in Microsoft Color Management Module Could Allow Remote Code Execution (901214)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the web client.

Description :

The remote host contains a version of the Color Management Module which
is vulnerable to a security flaw which may allow an attacker to execute
arbitrary code on the remote host by constructing a malicious web page
and entice a victim to visit this web page.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-036.mspx

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 901214";

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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Mscms.dll", version:"5.2.3790.359", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Mscms.dll", version:"5.2.3790.2476", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Mscms.dll", version:"5.1.2600.1710", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mscms.dll", version:"5.1.2600.2709", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mscms.dll", version:"5.0.2195.7054", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"901214") > 0 )
  security_hole(get_kb_item("SMB/transport"));
