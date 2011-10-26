#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11818);
 script_version("$Revision: 1.13 $");

 name["english"] = "The remote host is infected by msblast.exe";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote host is infected by a virus.

Description :

The remote host seems to be infected by the MS Blaster worm,
or the Nachi worm, and may make this host attack random hosts on the internet.

Solution :

 - http://securityresponse.symantec.com/avcenter/venc/data/w32.blaster.worm.html
 - http://securityresponse.symantec.com/avcenter/venc/data/w32.blaster.b.worm.html
 - http://securityresponse.symantec.com/avcenter/venc/data/w32.blaster.c.worm.html
 - http://securityresponse.symantec.com/avcenter/venc/data/w32.blaster.d.worm.html
 - http://securityresponse.symantec.com/avcenter/venc/data/w32.blaster.e.worm.html
 - http://securityresponse.symantec.com/avcenter/venc/data/w32.blaster.f.worm.html
 - http://www.symantec.com/avcenter/venc/data/w32.welchia.worm.html
 - http://www.microsoft.com/technet/security/bulletin/ms03-039.mspx

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of msblast.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");

 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
if(! get_kb_item("SMB/registry_access")) exit(0);

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

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 item = "windows auto update";
 array = RegQueryValue(handle:key_h, item:item);
 if(!isnull(array) && ("msblast.exe" >< tolower(array[1]) || "penis32.exe" >< tolower(array[1]) || "mspatch.exe" >< tolower(array[1]) ) )security_hole(port); 
 
 item = "microsoft inet xp..";
 array = RegQueryValue(handle:key_h, item:item);
 if ( ! isnull(array) && "teekids.exe" >< tolower( array[1] ) )
  security_hole(port); 

 item = "www.hidro.4t.com";
 array = RegQueryValue(handle:key_h, item:item);
 if ( ! isnull(array) && "enbiei.exe" >< tolower(array[1]) )
  security_hole(port); 

 item = "Windows Automation";
 array = RegQueryValue(handle:key_h, item:item);
 if ( ! isnull(array) && "mslaugh.exe" >< tolower(array[1]) )
  security_hole(port); 

 RegCloseKey(handle:key_h);
}


# Nachi

rootfile = hotfix_get_systemroot();


if ( ! rootfile )  {
	NetUseDel();
	exit(0);
	}

NetUseDel(close:FALSE);

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\wins\dllhost.exe", string:rootfile);


r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 )
{
 NetUseDel();
 exit(1);
}


handle = CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if( ! isnull(handle) )
{
 security_hole(port);
 CloseFile(handle:handle);
}

NetUseDel();

