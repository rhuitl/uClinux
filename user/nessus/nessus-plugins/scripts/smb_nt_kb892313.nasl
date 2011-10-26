#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(18085);
 script_bugtraq_id (13607);
 script_version("$Revision: 1.5 $");
 
 name["english"] = "DRM Update in Windows Media Player may facilitate spyware infections (892313)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to install spyware on the remote host.

Description :

The remote host is running a version Windows Media Player 9 or Windows Media 
Player 10 which contains a vulnerability which may allow an attacker to infect 
the remote host with spyware.

An attacker may exploit this flaw by crafting malformed WMP files which will
cause Windows Media Player to redirect the users to a rogue website when 
attempting to acquire a license to read the file.

Solution :

http://support.microsoft.com/kb/892313/

See also :

http://www.benedelman.org/news/010205-1.html

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of Media Player";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/WindowsMediaPlayer");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");

port = kb_smb_transport ();

version = get_kb_item("SMB/WindowsMediaPlayer");
if(!version)exit(0);

if ( ! is_accessible_share() ) exit(0);


if (ereg(string:version, pattern:"^9,0,0,.*"))
{
 if ( hotfix_check_sp(xp:3, win2k:5, win2003:2) <= 0 ) exit(0);
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Wmp.dll", version:"9.0.0.3263", min_version:"9.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.1", sp:1, file:"Wmp.dll", version:"9.0.0.3263", min_version:"9.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.0", file:"Wmp.dll", version:"9.0.0.3263", min_version:"9.0.0.0", dir:"\system32") )
    security_warning (port);

}

if (ereg(string:version, pattern:"^10,0,0,.*"))
{
 if ( hotfix_check_sp(xp:3, win2k:5, win2003:2) <= 0 ) exit(0);

  if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Wmp.dll", version:"10.0.0.3701", min_version:"10.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.1", sp:1, file:"Wmp.dll", version:"10.0.0.3701", min_version:"10.0.0.0", dir:"\system32") )
    security_warning (port);
}
   hotfix_check_fversion_end(); 
