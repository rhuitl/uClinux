#
# (C) Tenable Network Security
#


if (description) {
  script_id(18431);
  script_version("$Revision: 1.4 $");

  name["english"] = "AIM Detection";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote Windows host contains an instant-messaging application.

Description :

AOL Instant Messenger (AIM) is installed on the Windows host. AIM is
an instant-messaging application.

See also :

http://www.aim.com/index.adp

Solution :

Make sure the use of this program is in accordance with your corporate
security policy. 

Risk factor :

None";
  script_description(english:desc["english"]);
 
  summary["english"] = "Detects AOL Instant Messenger";
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
if (!soc) exit(1);
session_init(socket:soc, hostname:name);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) exit(0);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  NetUseDel();
  exit(0);
}


# Open the key used for AIM.
key = "SOFTWARE\America Online\AOL Instant Messenger";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (isnull(key_h)) {
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0);
}


# Grab installed version(s) of AIM (listed as subkeys of 'key_h').
info = RegQueryInfoKey(handle:key_h);
for (i=0; i<info[1]; ++i) {
 entries[i] = RegEnumKey(handle:key_h, index:i);
}


# Determine the newest version.
got_max = 0;
max = split("0.0.0", sep:".", keep:FALSE);
foreach entry (entries) {
  if (ereg(pattern:"[0-9]*\.[0-9]*\.[0-9]*", string:entry)) {
    ver = split(entry, sep:'.', keep:0);
    if (
      int(ver[0]) > int(max[0]) ||
      (int(ver[0]) == int(max[0]) && int(ver[1]) > int(max[1])) ||
      (int(ver[0]) == int(max[0]) && int(ver[1]) == int(max[1]) && int(ver[2]) > int(max[2]))
    ) {
      got_max = 1;
      max[0] = ver[0];
      max[1] = ver[1];
      max[2] = ver[2];
    }
  }
}


# Update KB and report findings.
if (got_max) {
  ver = string(max[0], ".", max[1], ".", max[2]);

  set_kb_item(name:"AIM/version", value:ver);

  report = string("AOL Instant Messenger ", ver, " was detected on the remote host.");
  security_note(port:port, data:report);
}


# Clean up.
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
NetUseDel();
