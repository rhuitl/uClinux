#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11363);
 script_bugtraq_id(6808);

 script_version("$Revision: 1.5 $");

 name["english"] = "Gupta SQLBase EXECUTE buffer overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of the Gupta SQLBase server
which is older than or equal to 8.1.0.

There is a flaw in this version which allows an attacker
to execute arbitrary code on this host, provided that
he can make SQL statements to it (usually thru a named pipe),
and therefore escalate privileges (and gain LocalSystem privileges).

Solution : Upgrade to version newer than 8.1.0
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of the remote Gupta SQLBase server";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 - 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");

if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);


name 	= kb_smb_name();
login	= kb_smb_login();
pass  	= kb_smb_password();
domain 	= kb_smb_domain();
port    = kb_smb_transport();
if(!get_port_state(port))exit(1);

soc = open_sock_tcp(port);
if(!soc)exit(1);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 exit(1);
}


key_h = RegOpenKey(handle:hklm, key:"SYSTEM\CurrentControlSet\Services\Gupta SQLBase", mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(1);
}


item = RegQueryValue(handle:key_h, item:"ImagePath");
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
if ( isnull(item) )
{
 NetUseDel();
 exit(1);
}

NetUseDel(close:FALSE);
rootfile = item[1];
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:rootfile);

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
 version = GetFileVersion(handle:handle);
 CloseFile(handle:handle);

 if ( !isnull(version) )
 {
  if ( version[0] < 8 ||
     (version[0] == 8  && version[1] == 0 ) ||
     (version[0] == 8  && version[1] == 1 && version[2] == 0 && version[3] == 0 ) )
    security_hole(port);
 }
}


NetUseDel();  
