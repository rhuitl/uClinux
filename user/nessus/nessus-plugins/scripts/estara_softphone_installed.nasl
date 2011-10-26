#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote Windows host is running a SIP client. 

Description :

The remote host is running eStara SoftPhone, a commercial SIP software
client for Windows. 

See also :

http://www.estara.com/softphone/

Risk factor : 

None";


if (description) {
  script_id(20957);
  script_version("$Revision: 1.2 $");

  script_name(english:"eStara SoftPhone Detection");
  script_summary(english:"Detects eStara SoftPhone");
 
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1);


# Make sure the software's installed.
prod = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/SoftPhone/DisplayName");
if (!prod) exit(0);


# Connect to the appropriate share.
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


# Determine where the software is installed.
key = "SOFTWARE\eStara\SoftPhone";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  item = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(item)) path = item[1];
  else path = NULL;

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


# If it appears to be installed...
if (path) {
  # Determine its version number from the executable itself.
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
  exe =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\softphone.exe", string:path);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1) {
    NetUseDel();
    exit(0);
  }

  fh = CreateFile(
    file:exe,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh)) {
    version = GetFileVersion(handle:fh);
    CloseFile(handle:fh);
  }

  # If available, save the version and report it.
  if (!isnull(version)) {
    ver = string(version[0], ".", version[1], ".", version[2], ".", version[3]);

    set_kb_item(name:"SMB/SoftPhone/Version", value:ver);

    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "  Product : eStara SoftPhone\n",
      "  Version : ", ver, "\n",
      "  Path    : ", path, "\n"
    );
    security_note(port:kb_smb_transport(), data:report);
  }
}


NetUseDel();
