#
# (C) Tenable Network Security
#


 desc = "
Synopsis :

There is an instant messaging client installed on the remote Windows
host. 

Description :

ICQ is installed on the remote host.  ICQ is an instant messaging
client for Windows that also includes some peer-to-peer file sharing
features.  As such, it may not be suitable for use in a business
environment. 

See also :

http://www.icq.com/

Solution : 

Remove this software if its use does not match your corporate security
policy. 

Risk factor : 

None";


if(description)
{
 script_id(11425);
 script_version("$Revision: 1.11 $");

 script_name(english:"ICQ is installed");
 
 script_description(english:desc);
 
 script_summary(english:"Determines if ICQ is installed");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2006 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1);


name	= kb_smb_name();
login	= kb_smb_login(); 
pass	= kb_smb_password(); 	
domain  = kb_smb_domain(); 	
port	= kb_smb_transport();

if ( ! get_port_state(port) ) exit(1);
soc = open_sock_tcp(port);
if ( ! soc ) exit(1);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) ) 
{
 NetUseDel();
 exit(1);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\ICQ.exe";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  prod = "ICQPro";

  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) exe = value[1];
  else exe = NULL;

  value = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(value)) path = value[1];
  else path = NULL;

  RegCloseKey(handle:key_h);
}
if (isnull(exe)) {
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\ICQLite.exe";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h)) {
    prod = "ICQLite";

    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value)) exe = value[1];
    else exe = NULL;

    value = RegQueryValue(handle:key_h, item:"Path");
    if (!isnull(value)) path = value[1];
    else path = NULL;

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);


if (exe && path) {
  # Determine its version from the executable itself.
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exe);
  exe2 =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exe);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1) {
    NetUseDel();
    exit(0);
  }

  fh = CreateFile(
    file:exe2,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh)) {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);
  }

  # If the version number's available, save and report it.
  if (!isnull(ver)) {
    version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);

    set_kb_item(name:"SMB/ICQ/Product", value:prod);
    set_kb_item(name:"SMB/ICQ/Version", value:version);
    set_kb_item(name:"SMB/ICQ/Path",    value:path);

    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "  Product : ", prod, "\n",
      "  Version : ", version, "\n",
      "  Path :    ", path, "\n"
    );
    security_note(port:kb_smb_transport(), data:report);
  }
}
NetUseDel();
