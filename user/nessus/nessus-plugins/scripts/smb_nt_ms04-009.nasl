#
# (C) Tenable Network Security
#

if(description)
{
 script_id(12092);
 script_bugtraq_id(9827);
 script_cve_id("CVE-2004-0121");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-B-0004");

 
 script_version("$Revision: 1.8 $");

 name["english"] = "Vulnerability in Outlook could allow code execution (828040)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the email client.

Description :

The remote host is running a version of outlook which is vulnerable to a bug 
which may allow Internet Explorer to execute script code in the Local Machine
zone and therefore let an attacker execute arbitrary programs on this host.

To exploit this bug, an attacker would need to send an special HTML message to
a user of this host.

Solution : 

Microsoft has released a set of patches for Office 2002 and XP :

http://www.microsoft.com/technet/security/bulletin/ms04-009.mspx

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of OutLook.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");

CommonFilesDir = hotfix_get_commonfilesdir();
if ( ! CommonFilesDir ) exit(1);





login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();
if(!get_port_state(port))exit(1);

soc = open_sock_tcp(port);
if(!soc)exit(1);

session_init(socket:soc, hostname:kb_smb_name());
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 exit(1);
}

key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\Microsoft\Office\10.0\Outlook\InstallRoot", mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(1);
}

value = RegQueryValue(handle:key_h, item:"Path");
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if ( isnull(value) ) 
{
 NetUseDel();
 exit(1);
}


share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:value[1]);
outlook =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\outlook.exe", string:value[1]);

r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 )
{
 NetUseDel();
 exit(1);
}

handle =  CreateFile (file:outlook, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(v) )
 {
  if ( v[0] == 10 && v[1] == 0 && v[2] < 5709 ) security_hole(port);
 }
}

NetUseDel();

