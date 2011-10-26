#
# (C) Tenable Network Security
#
if(description)
{
 script_id(11330);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2000-t-0008");
 script_bugtraq_id(1281);
 script_cve_id("CVE-2000-0402");
 script_version("$Revision: 1.8 $");

 name["english"] = "MS SQL7.0 Service Pack may leave passwords on system";

 script_name(english:name["english"]);
 
 desc["english"] = "
The installation process of the remote MS SQL server left 
files named 'sqlsp.log' on the remote host.

These files contain the password assigned to the 'sa' account
of the remote database.

An attacker may use this flaw to gain full administrative
access to your database.

See
http://www.microsoft.com/technet/security/bulletin/ms00-035.mspx

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Reads %temp%\sqlsp.log";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 - 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys( "SMB/WindowsVersion", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");



common = hotfix_get_systemroot();
if ( ! common ) exit(1);

port = kb_smb_transport();
if ( ! get_port_state(port) ) exit(1);

soc = open_sock_tcp(port);
if ( ! soc ) exit(1);

login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

session_init(socket:soc, hostname:kb_smb_name());
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 exit(1);
}

key_h = RegOpenKey(handle:hklm, key:"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0);
}

value = RegQueryValue(handle:key_h, item:"TEMP");
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if ( ! value )
{
 NetUseDel();
 exit(1);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:value[1]);
rootfile =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\sqlsp.log", string:value[1]);


r = NetUseAdd(login:kb_smb_login(), password:kb_smb_password(), domain:kb_smb_domain(), share:share);
if ( r != 1 ) exit(1);

handle =  CreateFile (file:rootfile, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

 if ( ! isnull(handle) ) 
 {
  CloseFile(handle:handle);
  security_warning(port);
 }

NetUseDel();
