#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18021);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0011");
 script_version("$Revision: 1.7 $");
 script_bugtraq_id(13112);
 script_cve_id("CVE-2005-0059");

 script_version("$Revision: 1.7 $");
 name["english"] = "Vulnerability in MSMQ Could Allow Code Execution (892944)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

The remote version of Windows is affected by a vulnerability in 
Microsoft Message Queuing Service (MSMQ).

An attacker may exploit this flaw to execute arbitrary code on the remote
host with the SYSTEM privileges.

Solution : 

Microsoft has released a set of patches for Windows 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms05-017.mspx

Risk factor : 

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if hotfix 892944 has been installed";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);

 script_dependencies("smb_hotfixes.nasl" );
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");

if ( hotfix_check_sp(xp:2, win2k:5) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Mqqm.dll", version:"5.1.0.1044", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mqqm.dll", version:"5.1.0.1044", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"892944") > 0  )
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

 key = "SOFTWARE\Microsoft\MSMQ\Setup";
 item = "InstalledComponents";
 key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
 if ( ! isnull(key_h) )
  value = RegQueryValue(handle:key_h, item:item);
 
 RegCloseKey (handle:hklm);
 NetUseDel();

 if ( !isnull(value) ) security_hole(port);
}
