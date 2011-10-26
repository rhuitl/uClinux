#
# This script was written by Tenable Network Security
#
# This script is released under Tenable Plugins License
#

if(description)
{
 script_id(11304);
 script_bugtraq_id(5004, 5005);
 script_version("$Revision: 1.13 $");
 script_cve_id("CVE-2002-0186", "CVE-2002-0187");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-B-0004");
 
 
 name["english"] = "Unchecked buffer in SQLXML";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through SQL server.

Description :

The remote host is running SQLXML. There are flaws in it which may
allow a remote attacker to execute arbitrary code on this host.

Solution :

Microsoft has released a set of patches for Office 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms02-030.mspx

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for SQLXML";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_full_access.nasl",
		     "mssql_version.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/registry_full_access","SMB/WindowsVersion");


 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");

port = get_kb_item("SMB/transport");
if(!port)port = 139;

version = get_kb_item("mssql/SQLVersion");
if(!version)exit(0);

# SP3 applied - don't know the version number yet
#if(ereg(pattern:"[8-9]\.00\.([8-9][0-9][0-9]|7[67][0-9])", string:version))exit(0);

access = get_kb_item("SMB/registry_full_access");
if(!access)exit(0);


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


key = "SYSTEM\CurrentControlSet\Services\SQLXML\Performance";
item = "Library";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);
 if (!isnull (value))
 {
  # If it's SQL Server Gold, then issue an alert.
  if(ereg(pattern:"^8\..*", string:version)) 
  {  
   key = "SOFTWARE\Microsoft\Updates\DataAccess\Q321858";
   key_h2 = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
   if ( isnull(key_h2) )
     security_hole (port);
   else
     RegCloseKey (handle:key_h2);
  }

  # SQLXML 2.0
  else if(ereg(pattern:".*sqlxml2\.dll", string:value))
  {
   key = "SOFTWARE\Microsoft\Updates\SQLXML 2.0\Q321460";
   key_h2 = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
   if ( isnull(key_h2) )
     security_hole (port);
   else
     RegCloseKey (handle:key_h2);
  }

  # SQLXML 3.0
  else if(ereg(pattern:".*sqlxml3\.dll", string:value))
  {
   key = "SOFTWARE\Microsoft\Updates\SQLXML 3.0\Q320833";
   key_h2 = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
   if ( isnull(key_h2) )
     security_hole (port);
   else
     RegCloseKey (handle:key_h2);
  }
 }

 RegCloseKey (handle:key_h);
}


RegCloseKey (handle:hklm);
NetUseDel ();
