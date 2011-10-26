#
# This script was written by Tenable Network Security
#
# This script is released under Tenable Plugins License
#

 desc["english"] = "
Synopsis :

Remote system is not up to date.

Description :

By reading the registry key HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CSDVersion
it was possible to determine that the remote Windows NT 4 system is not
up to date.

Solution :

Apply service pack 6a.

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";


if(description)
{
 script_id(10401);
 script_version ("$Revision: 1.31 $");
 script_cve_id("CVE-1999-0662");
 name["english"] = "SMB Registry : NT4 Service Pack version";
 
 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the remote SP";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_access.nasl");
 if ( defined_func("bn_random") ) script_dependencie("ssh_get_info.nasl");
 
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");

access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 139;


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

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
item = "CurrentVersion";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{

 value = RegQueryValue(handle:key_h, item:item);
 if (!isnull (value))
  set_kb_item(name:"SMB/WindowsVersion", value:value[1]);

 item = "CSDVersion";
 value2 = RegQueryValue(handle:key_h, item:item);
 if (!isnull (value2) )
 {
  set_kb_item(name:"SMB/CSDVersion", value:value2[1]);
  if(value[1] == "4.0")
  {
   set_kb_item(name:"SMB/WinNT4/ServicePack", value:value2[1]);
   if(ereg(string:value2[1], pattern:"^Service Pack [1-5]$"))
   {
    report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		"The remote WindowsNT is running ", value2[1]);

    security_hole(data:report, port:port);
   }
  }
  else if ( (value[1] == "5.0") && (value2[1] == "Service Pack 4"))
  {
   key = "SOFTWARE\Microsoft\Updates\Windows 2000\SP5\Update Rollup 1";
   key_h2 = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
   if ( ! isnull(key_h2) )
   {
    set_kb_item(name:"SMB/URP1", value:TRUE);
    RegCloseKey(handle:key_h2);  
   }
   else
   {
    key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\Update Rollup 1";
    key_h2 = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if ( ! isnull(key_h2) )
    {
     set_kb_item(name:"SMB/URP1", value:TRUE);
     RegCloseKey(handle:key_h2);  
    }
   }
  }

  RegCloseKey(handle:key_h);
 }
}

RegCloseKey(handle:hklm);
NetUseDel();
