#
#  (C) Tenable Network Security
#


 desc = "
Synopsis :

There is a peer-to-peer file sharing application installed on the
remote Windows host. 

Description :

Azureus is installed on the remote Windows host.  Azureus is an
open-source, Java-based, peer-to-peer file sharing application that
supports the BitTorrent protocol. 

Make sure the use of this program fits with your corporate security
policy. 

See also :

http://azureus.sourceforge.net/

Solution :

Remove this software if its use does not match your corporate security
policy. 

Risk factor : 

None";


if (description) {
  script_id(20844);
  script_version("$Revision: 1.3 $");

  script_name(english:"Azureus Detection");
  script_summary(english:"Checks for Azureus"); 
 
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


# Grab install path and version if it's installed.
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Azureus";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:"DisplayVersion");
  if (!isnull(value)) ver = value[1];

  value = RegQueryValue(handle:key_h, item:"InstallLocation");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


# If the information is available, save and report it.
if (!isnull(ver) && !isnull(path)) {
  set_kb_item(name:"SMB/Azureus/Version", value:ver);

    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Version ", ver, " of Azureus is installed under :\n",
      "  ", path, "\n"
    );

  security_note(port:kb_smb_transport(), data:report);
}


# Clean up.
NetUseDel();
