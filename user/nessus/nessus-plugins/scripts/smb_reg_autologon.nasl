#
# This script was written by Tenable Network Security
#
# This script is released under Tenable Plugins License
#

 desc["english"] = "
Synopsis :

Anyone can logon to the remote system.

Description :

This script determines whether the autologon feature is enabled.
This feature allows an intruder to log into the remote host as 
DefaultUserName with the password DefaultPassword.

Solution : 

Delete the keys AutoAdminLogon and DefaultPassword under
HKLM\SOFTWARE\Microsoft\Window NT\CurrentVersion\Winlogon

See also : 

http://www.microsoft.com/windows2000/techinfo/reskit/en-us/regentry/12315.asp

Risk factor :

High / CVSS Base Score : 7 
(AV:L/AC:L/Au:NR/C:C/A:C/I:C/B:N)";


if(description)
{
 script_id(10412);
 script_version ("$Revision: 1.19 $");
 
 name["english"] = "SMB Registry : Autologon";

 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if the autologon feature is installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_access.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");

port = get_kb_item("SMB/transport");
if(!port)port = 139;

name	= kb_smb_name(); 	if(!name)exit(0);
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


key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
item1 = "DefaultUserName";
item2 = "DefaultPassword";
item3 = "AutoAdminLogon";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value1 = RegQueryValue(handle:key_h, item:item1);
 value2 = RegQueryValue(handle:key_h, item:item2);
 value3 = RegQueryValue(handle:key_h, item:item3);

 if ((!isnull(value3) && (value3[1] != "0")) && (!isnull (value1) && !isnull(value2)))
 {
  rep = 'Autologon is enabled on this host.\n' +
        "This allows an attacker to access it as " + value1[1] + "/" + value2[1];
  
  report = desc["english"] + '\n\nPlugin output :\n\n' + rep;

  security_hole(port:port, data:report);
 }

 RegCloseKey (handle:key_h);
}

RegCloseKey (handle:hklm);
NetUseDel ();
