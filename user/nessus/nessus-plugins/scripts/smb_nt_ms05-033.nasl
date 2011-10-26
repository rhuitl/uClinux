#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18486);
 script_version("$Revision: 1.6 $");
 script_bugtraq_id(13940);
 script_cve_id("CVE-2005-1205");

 name["english"] = "Vulnerability in Telnet Client Could Allow Information Disclosure (896428)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to disclose user information.

Description :

The remote version of Windows contains a flaw the Telnet client which
may allow an attacker to read the session variables of users connecting
to a rogue telnet server.

Solution : 

Microsoft has released a set of patches for Windows XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-033.mspx

Risk factor : 

Low / CVSS Base Score : 3 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 896428";

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


if ( hotfix_check_sp(xp:3, win2003:2) > 0 ) 
{
 if (is_accessible_share())
 {
  if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"telnet.exe", version:"5.2.3790.329", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.2", sp:1, file:"telnet.exe", version:"5.2.3790.2442", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.1", sp:1, file:"telnet.exe", version:"5.1.2600.1684", dir:"\system32") ||
       hotfix_is_vulnerable (os:"5.1", sp:2, file:"telnet.exe", version:"5.1.2600.2674", dir:"\system32") )
    security_note (get_kb_item("SMB/transport"));
 
  hotfix_check_fversion_end(); 
  exit (0);
 }
 else if ( hotfix_missing(name:"896428") > 0 )
	 security_note(get_kb_item("SMB/transport"));
}

if ( hotfix_check_sp(win2k:6) > 0  && hotfix_missing(name:"896428") > 0 ) 
{
 name	= kb_smb_name(); 	
 login	= kb_smb_login(); 
 pass	= kb_smb_password(); 	
 domain  = kb_smb_domain(); 	
 port	= kb_smb_transport();

 if ( ! get_port_state(port) ) exit(0);
 soc = open_sock_tcp(port);
 if ( ! soc ) exit(0);

 session_init(socket:soc, hostname:name);
 r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
 if ( r != 1 ) exit(0);

 hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
 if ( isnull(hklm) ) 
 {
  NetUseDel();
  exit(0);
 }

 key = "SOFTWARE\Microsoft\Services for Unix";
 item = "InstallPath";
 key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
 if ( ! isnull(key_h) )
  value = RegQueryValue(handle:key_h, item:item);
 
 RegCloseKey (handle:hklm);
 NetUseDel();

 if ( !isnull(value) ) security_note(get_kb_item("SMB/transport"));
}
