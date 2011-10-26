#
# (C) Tenable Network Security
#
# See the Nessus Scripts License for details
#
# 
# Ref: http://archives.neohapsis.com/archives/bugtraq/2003-05/0117.html


if(description)
{
 script_id(11631);
 script_version("$Revision: 1.4 $");

 name["english"] = "Drag And Zip Overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Drag And Zip - a file compression utility.

There is a flaw in this program which may allow a remote attacker to
execute arbitrary code on this host.

To exploit this flaw, an attacker would need to craft a special
Zip file and send it to a user on this host. Then, the user would
need to open it using Drag And Zip.

Solution : None
Risk factor : Low";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of Drag And Zip";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(0);

include("smb_func.inc");



name 	= kb_smb_name();
login	= kb_smb_login();
pass  	= kb_smb_password();
domain 	= kb_smb_domain();
port    = kb_smb_transport();
if(!port) port = 139;


if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

session_init(socket:soc, hostname:name);

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 exit(1);
}

key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\Canyon\InstalledApps\DragAndZip", mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 NetUseDel();
 exit(0);
}

value = RegQueryValue(handle:key_h, item:"Install Directory");
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if ( isnull(value) ) {
	NetUseDel();
	exit(0);
}

rootfile = value[1];
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
exe =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Dz32.exe", string:rootfile);


r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) 
{
 NetUseDel();
 exit(0);
}

handle = CreateFile (file:exe, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if( ! isnull(handle) )
{
 security_warning(port);
 CloseFile(handle:handle);
}

NetUseDel();
