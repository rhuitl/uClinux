#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote Windows host contains an alternative web browser. 

Description :

Netscape Browser or Netscape Navigator, alternative web browsers, is
installed on the remote Windows host. 

See also :

http://browser.netscape.com/

Risk factor :

None";


if (description) {
  script_id(19695);
  script_version("$Revision: 1.2 $");

  name["english"] = "Netscape Browser Detection";
  script_name(english:name["english"]);

  script_description(english:desc["english"]);
 
  summary["english"] = "Detects Netscape Browser";
  script_summary(english:summary["english"]);

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


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
name = kb_smb_name();
port = kb_smb_transport();
if (!get_port_state(port)) exit(0);
login = kb_smb_login();
pass = kb_smb_password();
domain = kb_smb_domain();


# Connect to the remote registry.
soc = open_sock_tcp(port);
if (!soc) exit(0);
session_init(socket:soc, hostname:name);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) exit(0);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  NetUseDel();
  exit(0);
}


# Get the software's version.
#
# - Netscape Browser.
key = "SOFTWARE\Netscape\Netscape Browser";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:"CurrentVersion");
  if (!isnull(value)) ver_browser = value[1];

  RegCloseKey(handle:key_h);
}

# - Netscape Navigator.
key = "SOFTWARE\Netscape\Netscape";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:"CurrentVersion");
  if (!isnull(value)) ver_navigator = value[1];

  RegCloseKey(handle:key_h);
}


# Clean up.
RegCloseKey(handle:hklm);
NetUseDel();


# Update KB and report findings.
#
# nb: version will look like "8.0.3.3 (en-US)".
if (ver_browser) {
  set_kb_item(name:"Netscape/Browser/Version", value:ver_browser);

  info = string("Netscape Browser version ", ver_browser, " was detected on the remote host.");
  report = string(
    desc["english"],
    "\n\n",
    "Plugin output :\n",
    "\n",
    info
  );
  security_note(port:port, data:report);
}

# nb: version will look like "7.2 (en)".
if (ver_navigator) {
  set_kb_item(name:"Netscape/Navigator/Version", value:ver_navigator);

  info = string("Netscape Navigator version ", ver_navigator, " was detected on the remote host.");
  report = string(
    desc["english"],
    "\n\n",
    "Plugin output :\n",
    "\n",
    info
  );
  security_note(port:port, data:report);
}
