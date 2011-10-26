#
# This script was written by Tenable Network Security
#
# This script is released under Tenable Plugins License
#

if(description)
{
 script_id(10428);
 script_version ("$Revision: 1.29 $");
 
 name["english"] = "SMB fully accessible registry";
 
 script_name(english:name["english"]);
 
 desc["english"] = "

Nessus did not access the remote registry completely,
because this needs to be logged in as administrator.

If you want the permissions / values of all the sensitive
registry keys to be checked for, we recommend that
you fill the 'SMB Login' options in the
'Prefs.' section of the client by the administrator
login name and password.

Risk factor : None";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether the remote registry is fully accessible";
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

access = get_kb_item("SMB/registry_access");
if(!access)exit(0);


#---------------------------------------------------------------------#
# Here is our main()                                                  #
#---------------------------------------------------------------------#

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

full = 0;

key = "SOFTWARE\Microsoft\Internet Explorer\Version Vector";
item = "IE";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);
 if (!isnull (value))
 {
  full = 1;
  set_kb_item(name:"SMB/registry_full_access", value:TRUE);
 }

 RegCloseKey (handle:key_h);
}

if (full == 0)
{
 key = "SOFTWARE\Microsoft\Internet Explorer";
 item = "IVer";

 key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
 if ( ! isnull(key_h) )
 {
  value = RegQueryValue(handle:key_h, item:item);
  if (!isnull (value))
  {
   full = 1;
   set_kb_item(name:"SMB/registry_full_access", value:TRUE);
  }

  RegCloseKey (handle:key_h);
 }
}

RegCloseKey(handle:hklm);
NetUseDel();

if (full == 0)
  security_note (port);
