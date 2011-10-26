#
#
# (C) Tenable Network Security
#
#
# Fixed in Windows XP SP1
#
# Vulnerable versions :
# 	Media Player in Windows XP preSP1 
# 	Media Player 6.4
#	Media Player 7.1
#
#
# Supercedes MS01-056
#

if(description)
{
 script_id(11302);
 script_bugtraq_id(5107, 5109, 5110);
 script_version("$Revision: 1.13 $");
 script_cve_id("CVE-2002-0372", "CVE-2002-0373", "CVE-2002-0615");
 
 
 name["english"] = "Cumulative patch for Windows Media Player";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the media player.

Description :

The remote version of Windows Media Player is vulnerable to various flaws :
- A remote attacker may be able to execute arbitrary code  when sending a 
  badly formed file
	  
- A local attacker may gain SYSTEM privileges

Solution :

Microsoft has released a set of patches for Windows XP :

http://www.microsoft.com/technet/security/bulletin/ms02-032.mspx

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of Media Player";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 - 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");

access = get_kb_item("SMB/registry_full_access");
if(!access)exit(0);

version = get_kb_item("SMB/WindowsVersion");

if("5.1" >< version)
{
  # This is windows XP
  sp = get_kb_item("SMB/WinXP/ServicePack");
  if(sp && ereg(pattern:"Service Pack [1-9]", string:sp))exit(0);
  security_hole(port);
  exit(0);
}



name	= kb_smb_name(); 	if(!name)exit(0);
login	= kb_smb_login(); 
pass	= kb_smb_password(); 	
domain  = kb_smb_domain(); 	
port	= kb_smb_transport();

if ( ! get_port_state(port) ) exit(1);
soc = open_sock_tcp(port);
if ( ! soc ) exit(1);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 exit(1);
}

key = "SOFTWARE\Microsoft\MediaPlayer\7.0\Registration";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED); 
if(!isnull(key_h))
{
 item = RegQueryValue(handle:key_h, item:"UDBVersion");
 RegCloseKey(handle:key_h);
 if ( isnull(item) )
 {
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0);
 }
}


if(ereg(pattern:"^7\.01\..*", string:item[1]) ||
   ereg(pattern:"^6\.04\..*", string:item[1]))
{
  key = "SOFTWARE\Microsoft\Updates\Windows Media Player\wm320920.1";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED); 
  if ( isnull(key_h) ) security_hole(port);
  else RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);
NetUseDel();
