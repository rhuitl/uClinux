#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

There is a media player installed on the remote Windows host. 

Description :

QuickTime is installed on the remote host.  QuickTime is a popular
media player / plug-in that handles various types of music and video
files. 

Make sure the use of this program fits with your corporate security
policy. 

See also :

http://www.apple.com/quicktime/

Solution :

Remove this software if its use does not match your corporate security
policy. 

Risk factor : 

None";


if (description)
{
  script_id(21561);
  script_version("$Revision: 1.1 $");

  script_name(english:"QuickTime Detection");
  script_summary(english:"Checks Windows registry for QuickTime");
 
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("http_func.inc");
include("misc_func.inc");
include("smb_func.inc");


# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);

name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) exit(0);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(0);

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Get some info about the install.
key = "SOFTWARE\Apple Computer, Inc.\QuickTime";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallDir");
  if (!isnull(item)) path = item[1];
  else path = NULL;

  item = RegQueryValue(handle:key_h, item:"Version");
  if (!isnull(item)) ver = item[1];
  else ver = NULL;

  RegCloseKey(handle:key_h);
}
else
{
  path = NULL;
  ver = NULL;
}
RegCloseKey(handle:hklm);
NetUseDel();


# Generate report and save info in KB.
if (path && ver) 
{
  hver = hexstr(dec2hex(num:ver));
  version = hex2dec(xvalue:substr(hver, 0, 1)) + "." +
    hex2dec(xvalue:substr(hver, 2, 2)) + "." + 
    hex2dec(xvalue:substr(hver, 3, 3));
  path =  ereg_replace(pattern:"(.*)\\", replace:"\1", string:path);

  set_kb_item(name:"SMB/QuickTime/Version", value:version);
  set_kb_item(name:"SMB/QuickTime/Path",    value:path);

  report = string(
    desc,
    "\n\n",
    "Plugin output :\n",
    "\n",
    "  Version : ", version, "\n",
    "  Path    : ", path, "\n"
  );
  security_note(port:kb_smb_transport(), data:report);
}
