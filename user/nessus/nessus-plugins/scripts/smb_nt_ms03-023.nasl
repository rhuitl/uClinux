#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11878);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-b-0004");
 script_bugtraq_id(8016);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2003-0469");
 
 name["english"] = "Buffer Overrun In HTML Converter Could Allow Code Execution (823559)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the web client.

Description :

The remote host contains a version of the HTML Converter module which is
vulnerable to a security flaw which may allow an attacker to execute arbitrary
code on the remote host by constructing a malicious web page and entice a
victim to visit this web page.

Solution : 

Microsoft has released a set of patches for Windows NT, 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms03-023.mspx

Risk factor :

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix Q823559";

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


if ( hotfix_check_sp(nt:7, win2k:5, xp:2, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 path = hotfix_get_commonfilesdir() + "\Microsoft Shared\TextConv";

 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Msconv97.dll", version:"2003.1100.5426.0", dir:path) ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Msconv97.dll", version:"2003.1100.5426.0", dir:path) ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Msconv97.dll", version:"2003.1100.5426.0", dir:path) ||
      hotfix_is_vulnerable (os:"5.0", file:"Msconv97.dll", version:"2003.1100.5426.0", dir:path) ||
      hotfix_is_vulnerable (os:"4.0", file:"Msconv97.dll", version:"2003.1100.5426.0", dir:path) )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"KB823559") > 0 )
	security_hole(get_kb_item("SMB/transport"));
