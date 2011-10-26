#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote Windows host is running BlackBerry Enterprise Server.

Description :

The remote host is running BlackBerry Enterprise Server, a software
suite for linking wireless networks and devices with enterprise
messaging and application servers. 

See also :

http://www.blackberry.com/products/software/index.shtml

Risk factor : 

None";


if (description) {
  script_id(20949);
  script_version("$Revision: 1.2 $");

  script_name(english:"BlackBerry Enterprise Server Detection");
  script_summary(english:"Detects BlackBerry Enterprise Server");
 
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


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
if (rc != 1) {
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  NetUseDel();
  exit(0);
}


# Get some info about the install.
key = "SOFTWARE\Research In Motion\BlackBerry Enterprise Server\Setup";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  item = RegQueryValue(handle:key_h, item:"BasePath");
  if (!isnull(item)) path = item[1];
  else path = NULL;

  # nb: this leads to the actual product installed, including any
  # service packs / hotfixes.
  item = RegQueryValue(handle:key_h, item:"ConfigProductCode");
  if (!isnull(item)) subkey = item[1];
  else subkey = NULL;

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel();

if (isnull(path) || isnull(subkey)) exit(0);

# Get info about the current install.
key = string("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/", subkey, "/DisplayName");
name = get_kb_item(key);

key = string("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/", subkey, "/DisplayVersion");
ver = get_kb_item(key);


# Generate report and save info in KB.
if (name && ver) {
    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "  Product : ", name, "\n",
      "  Version : ", ver, "\n",
      "  Path    : ", path, "\n"
    );
  security_note(port:kb_smb_transport(), data:report);

  set_kb_item(name:"BlackBerry_ES/Product", value:name);
  set_kb_item(name:"BlackBerry_ES/Version", value:ver);
  set_kb_item(name:"BlackBerry_ES/Path",    value:path);
}
