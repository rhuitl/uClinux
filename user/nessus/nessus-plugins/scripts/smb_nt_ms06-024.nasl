#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(21688);
 script_version("$Revision: 1.4 $");
 script_cve_id("CVE-2006-0025");
 script_bugtraq_id(18385);
 
 name["english"] = "Vulnerability in Windows Media Player Could Allow Remote Code Execution (917734)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the Media Player.

Description :

The remote host is running Windows Media Player.

There is a vulnerability in the remote version of this software which may
allow an attacker to execute arbitrary code on the remote host.

To exploit this flaw, one attacker would need to set up a rogue
PNG image and send it to a victim on the remote host.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-024.mspx

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of Media Player";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
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

port = kb_smb_transport ();
patched = 0;


if ( hotfix_check_sp(xp:3, win2k:6, win2003:2) <= 0 ) exit(0);

version = get_kb_item("SMB/WindowsMediaPlayer");
if(!version)exit(0);


if (is_accessible_share())
{
  if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Wmp.dll", version:"9.0.0.3349", min_version:"9.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.2", file:"Wmp.dll", version:"10.0.0.3704", min_version:"10.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.1", file:"Wmp.dll", version:"9.0.0.3349", min_version:"9.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.1", sp:1, file:"Wmpui.dll", version:"8.0.0.4496", min_version:"8.0.0.0", dir:"\system32") || 
       hotfix_is_vulnerable (os:"5.1", file:"Wmp.dll", version:"10.0.0.4036", min_version:"10.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.0", file:"Wmpui.dll", version:"7.10.0.3078", min_version:"7.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.0", file:"Wmp.dll", version:"9.0.0.3349", min_version:"9.0.0.0", dir:"\system32") )
    security_warning(port);

   hotfix_check_fversion_end(); 
}
else
{
  if ( hotfix_missing(name:"917734") > 0  )
    security_warning(port);
}

