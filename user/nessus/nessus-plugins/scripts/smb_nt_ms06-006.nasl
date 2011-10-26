#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(20906);
 script_version("$Revision: 1.3 $");
 script_cve_id("CVE-2006-0005");
 script_bugtraq_id(16644);
 
 name["english"] = "Vulnerability in Windows Media Player Plug-in Could Allow Remote Code Execution (911564)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the Media Player.

Description :

The remote host is running either Windows Media Player plug-in.

There is a vulnerability in the remote version of this software which may
allow an attacker to execute arbitrary code on the remote host.

To exploit this flaw, one attacker would need to set up a rogue
EMBED element and send it to a victim on the remote host.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-006.mspx

Risk factor : 

Medium / CVSS Base Score : 4.8
(AV:L/AC:L/Au:NR/C:P/I:P/A:P/B:N)";

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

if ( hotfix_check_sp(xp:3, win2k:6, win2003:2) <= 0 ) exit(0);


path = get_kb_item("SMB/WindowsMediaPlayer_path");
if(!path)exit(0);

if (is_accessible_share())
{
  if ( hotfix_check_fversion(path:path, file:"Npdsplay.dll", version:"3.0.2.629") == HCF_OLDER ) security_warning(port);

   hotfix_check_fversion_end(); 
}
else
{
  if ( hotfix_missing(name:"911564") > 0  )
    security_warning(port);
}

