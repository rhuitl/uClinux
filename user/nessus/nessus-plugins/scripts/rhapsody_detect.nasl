#
# (C) Tenable Network Security
#
# 


  desc = "
Synopsis :

There is a music-playing application installed on the remote Windows
host. 

Description :

Rhapsody is installed on the remote Windows host.  Rhapsody is a music
service and media player from RealNetworks. 

Make sure the use of this program fits with your corporate security
policy. 

See also :

http://www.rhapsody.com/

Solution :

Remove this software if its use does not match your corporate security
policy. 

Risk factor : 

None";

 
if (description) {
  script_id(18559);
  script_version("$Revision: 1.4 $");

  script_name(english:"Rhapsody Detection");
  script_summary(english:"Detects Rhapsody");

  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1);
name = kb_smb_name();
port = kb_smb_transport();
if (!get_port_state(port)) exit(1);
login = kb_smb_login();
pass = kb_smb_password();
domain = kb_smb_domain();


# Connect to the remote registry.
soc = open_sock_tcp(port);
if (!soc) exit(1);
session_init(socket:soc, hostname:name);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  NetUseDel();
  exit(1);
}


# Determine if it's installed.
key = "SOFTWARE\Wise Solutions\WiseUpdate\Apps\Rhapsody";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:"Version");
  if (!isnull(value)) ver = value[1];
  else ver = NULL;

  RegCloseKey(handle:key_h);
}
if (isnull(ver))
{
  key = "SOFTWARE\Wise Solutions\WiseUpdate\Apps\Listen Rhapsody";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h)) {
    value = RegQueryValue(handle:key_h, item:"Version");
    if (!isnull(value)) ver = value[1];
    else ver = NULL;

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);
NetUseDel();


# Update KB and report findings.
if (!isnull(ver))
{
  set_kb_item(name:"SMB/Rhapsody/Version", value:ver);

  iver = split(ver, sep:'.', keep:FALSE);
  alt_ver = string(iver[0], " build ", iver[1], ".", iver[2], ".", iver[3]);
  report = string(
    desc,
    "\n\n",
    "Plugin output :\n",
    "\n",
    "Version ", alt_ver, " of Rhapsody is installed.\n"
  );

  security_note(port:kb_smb_transport(), data:report);
}
