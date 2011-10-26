#
#  (C) Tenable Network Security
#


 desc = "
Synopsis :

There is a peer-to-peer file sharing application installed on the
remote Windows host. 

Description :

BitLord is installed on the remote Windows host.  BitLord is a
freeware peer-to-peer file sharing application that supports the
BitTorrent protocol. 

Make sure the use of this program fits with your corporate security
policy. 

See also :

http://www.bitlord.com/

Solution :

Remove this software if its use does not match your corporate security
policy. 

Risk factor : 

None";


if (description) {
  script_id(20845);
  script_version("$Revision: 1.2 $");

  script_name(english:"BitLord Detection");
  script_summary(english:"Checks for BitLord"); 
 
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
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
  if (log_verbosity > 1) debug_print("can't connect to the remote registry!", level:0);
  NetUseDel();
  exit(0);
}


# Determine if it's installed.
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\BitLord.exe";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) exe = value[1];
  RegCloseKey(handle:key_h);
}
if (isnull(exe) && thorough_tests) {
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\BitLord\DisplayIcon";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h)) {
    value = RegQueryValue(handle:key_h, item:"DisplayIcon");
    if (!isnull(value)) exe = value[1];
    RegCloseKey(handle:key_h);
  }
}
if (isnull(exe) && thorough_tests) {
  key = "SOFTWARE\Classes\bittorrent\shell\open\command";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h)) {
    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value)) {
      # nb: the exe itself appears in quotes.
      exe = ereg_replace(pattern:'^"([^"]+)".*', replace:"\1", string:value[1]);
    }
    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);


# If it is...
if (exe) {
  # Determine its version from the executable itself.
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exe);
  exe2 =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exe);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1) {
    if (log_verbosity > 1) debug_print("can't connect to the remote share (", rc, ")!", level:0);
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
    # nb: GetFileVersion returns more detail than the product 
    #     version; eg, "1.1.5.6" versus "1.1"
    version = GetFileVersion(handle:fh);
    ver = string(version[0], ".", version[1], ".", version[2], ".", version[3]);
    CloseFile(handle:fh);
  }

  # If the version number's available, save and report it.
  if (!isnull(ver)) {
    set_kb_item(name:"SMB/BitLord/Version", value:ver);

      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Version ", ver, " of BitLord is installed as :\n",
        "  ", exe, "\n"
      );
    security_note(port:kb_smb_transport(), data:report);
  }
}


# Clean up.
NetUseDel();
