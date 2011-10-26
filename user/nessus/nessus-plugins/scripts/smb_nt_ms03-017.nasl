#
# This script was written by Tenable Network Security
#
# This script is released under Tenable Plugins License
#
#
# Fixed in Windows XP SP1
#
# Vulnerable versions :
# 	Media Player in Windows XP preSP2
#	Media Player 7.1
#
#

if(description)
{
 script_id(11595);
 script_bugtraq_id(7517);
 script_version("$Revision: 1.14 $");
 script_cve_id("CVE-2003-0228");
 
 name["english"] = "Windows Media Player Skin Download Overflow";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the media player.

Description :

The remote host is using a version of Windows Media player which is
vulnerable to a directory traversal through its handling of 'skins'.

An attacker may exploit this flaw to execute arbitrary code on this
host with the privileges of the user running Windows Media Player.

To exploit this flaw, one attacker would need to craft a specially
malformed skin and send it to a user of this host, either directly
by e-mail or by sending a URL pointing to it.

Affected Software:

 - Microsoft Windows Media Player 7.1
 - Microsoft Windows Media Player for Windows XP (Version 8.0)

Solution : 

Microsoft has released a set of patches for Windows Media Player :

http://www.microsoft.com/technet/security/bulletin/ms03-017.mspx

Risk factor :

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of Media Player";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys( "SMB/WindowsVersion", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_sp(xp:2) <= 0 ) exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 139;

access = get_kb_item("SMB/registry_full_access");
if(!access)exit(0);

version = get_kb_item("SMB/WindowsMediaPlayer");
if(!version)exit(0);


if (is_accessible_share())
{
 path = hotfix_get_systemroot() + "\system32";

 if ( hotfix_check_fversion(path:path, file:"Wmplayer.exe", version:"8.0.0.4490", min_version:"8.0.0.0") == HCF_OLDER ) security_hole(port);
 if ( hotfix_check_fversion(path:path, file:"Wmplayer.exe", version:"7.10.0.3074", min_version:"7.10.0.0") == HCF_OLDER ) security_hole(port);

 hotfix_check_fversion_end();
 
 exit (0);
}
else
{
 fix = get_kb_item ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Updates/Windows Media Player/wm817787");
 if(!fix) security_hole(port);
}