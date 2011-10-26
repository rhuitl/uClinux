#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote web server contains a web-hosting automation application
written in ASP. 

Description :

The remote host is running Hosting Controller, a commercial web-
hosting automation suite for the Windows Server family platform. 

See also : 

http://hostingcontroller.com/

Risk factor :

None";


if (description) {
  script_id(19254);
  script_version("$Revision: 1.2 $");

  name["english"] = "Hosting Controller Detection";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Detects Hosting Controller";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Look in the registry for the version of Hosting Controller installed.
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
if (rc != 1) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  NetUseDel();
  exit(1);
}


# Determine the version / hotfix number of Hosting Controller.
key = "SOFTWARE\Advanced Communications\Nt Web Hosting Controller\General";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:"Version");
  if (!isnull(value)) ver = value[1];

  value = RegQueryValue(handle:key_h, item:"HCAdminSitePort");
  if (!isnull(value)) hc_port = value[1];

  value = RegQueryValue(handle:key_h, item:"LatestServicePack");
  if (!isnull(value)) hotfix = value[1];

  RegCloseKey(handle:key_h);
}


# Clean up.
RegCloseKey(handle:hklm);
NetUseDel();


# Update the KB and report if it's installed.
if (ver && hc_port) {
  if (hotfix) ver = string(ver, " hotfix ", hotfix);

  set_kb_item(
    name:string("www/", hc_port, "/hosting_controller"),
    value:string(ver)
  );

  info = string("Hosting Controller ", ver, " was detected on the remote host running\non port ", hc_port, ".");
  report = string(
    desc["english"],
    "\n\n",
    "Plugin output :\n",
    "\n",
    info
  );
  security_note(port:hc_port, data:report);
}
