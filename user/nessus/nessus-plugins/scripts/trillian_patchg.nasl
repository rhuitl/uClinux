#
# Copyright (C) 2004 Tenable Network Security
#
if(description)
{
 script_id(12076);
 script_version("$Revision: 1.7 $");

 name["english"] = "Trillian remote Overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
Trillian is a Peer2Peer client that allows users to chat and share files
with other users across the world.  A bug has been reported in the AOL 
Instant Messenger (AIM) portion of Trillian.  A remote attacker, exploiting
this flaw, would be potentially able to execute code on the client system
running Trillian.

Solution: Upgrade to Trillian 0.74 patch G (or higher)

See also: http://security.e-matters.de/advisories/022004.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Trillian.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");

if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);

# reg value = "C:\Program Files\Trillian\trillian.exe -command="%1"   "


name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();


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

key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\Classes\AIM\shell\open\command", mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0);
}

value = RegQueryValue(handle:key_h, item:"Default");
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if ( isnull(value) ) {
	NetUseDel();
	exit(1);
}

rootfile = hotfix_get_programfilesdir();
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
findash = strstr(rootfile, "-command");
file = rootfile - findash;

r = NetUseAdd(login:login, password:pass,domain:domain, share:share);
if ( r != 1 )
{
 NetUseDel();
 exit(1);
}

handle = CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);


if ( ! isnull(handle) )
{
 # C:\Program Files\Trillian>find /N /i "v0.7" trillian.exe
 #
 #---------- TRILLIAN.EXE
 #[31288]v0.74 (w/ Patch G) - February 2004

 off = 31200;
 data = ReadFile(handle:handle, length:512, offset:off);
 CloseFile(handle:handle);
 data = str_replace(find:raw_string(0), replace:"", string:data);
 version = strstr(data, "v0.7");
 if ( version )
 {
  hopup = strstr(data, " - ");
  v = version - hopup;
  set_kb_item(name:"Host/Windows/Trillian/Version", value:v);
  if (egrep(string:v, pattern:"v0\.7[1-4].*")) {
    if (! egrep(string:v, pattern:"\(w/ Patch [G-Z]\)")) security_hole(port);
  }
 }
}

NetUseDel();
