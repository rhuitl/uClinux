#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(16328);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2004-1244", "CVE-2004-0597");
 script_bugtraq_id(12485, 12506);
 if ( defined_func("script_xref") ) script_xref(name:"IAVA", value:"2005-B-0006");

 
 name["english"] = "Vulnerability in PNG Processing Could Allow Remote Code Execution (890261)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the Media Player.

Description :

The remote host is running either Windows Media Player 9 or MSN Messenger.

There is a vulnerability in the remote version of this software which may
allow an attacker to execute arbitrary code on the remote host.

To exploit this flaw, one attacker would need to set up a rogue
PNG image and send it to a victim on the remote host.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-009.mspx

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
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access","SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");

port = get_kb_item("SMB/transport");
if(!port) port = 139;

patched = 0;

if (report_paranoia >= 1)
{
 if ( hotfix_check_sp(xp:2) > 0 ) # XP < SP2
 {
  # Messenger 4.7.0.2009 on XP SP1
  key = get_kb_item ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Active Setup/Installed Components/{5945c046-1e7d-11d1-bc44-00c04fd912be}/Version");
  if (!key)
    security_hole(port);
  else
   patched++;
 }
 else if ( hotfix_check_sp(xp:3) > 0 ) # XP < SP3
 {
   version = get_kb_item("SMB/WindowsMediaPlayer");
  if(!version)exit(0);
  if (ereg(string:version, pattern:"^(9|10),0,0,.*"))patched ++;
  else 
  {
   # Messenger 4.7.0.3000 on XP SP2
   if ( hotfix_missing(name:"887472") > 0 ) security_hole(port);
   else patched ++;
  }
 }
}


# Check Windows Media Player 9
if ( hotfix_check_sp(xp:2, win2k:5, win2003:1) <= 0 ) exit(0);

version = get_kb_item("SMB/WindowsMediaPlayer");
if(!version)exit(0);


if (ereg(string:version, pattern:"^9,0,0,.*"))
{
 if (is_accessible_share())
 {
  if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Wmp.dll", version:"9.0.0.3250", min_version:"9.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.1", sp:1, file:"Wmp.dll", version:"9.0.0.3250", min_version:"9.0.0.0", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.0", file:"Wmp.dll", version:"9.0.0.3250", min_version:"9.0.0.0", dir:"\system32") )
    security_hole (get_kb_item("SMB/transport"));
  else
    patched ++; 
   hotfix_check_fversion_end(); 
 }
 else
 {
  # The update is in HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Updates\Windows Media Player\wm885492
  if ( hotfix_missing(name:"885492") > 0  && hotfix_missing(name:"911565") > 0)
    security_hole(port);
  else
    patched ++;
 }
}

if ( patched )
	set_kb_item(name:"SMB/890261", value:TRUE);


