#
#  (C) Tenable Network Security
#


 desc = "
Synopsis :

The remote Windows host contains one or more applications from
Mozilla.org. 

Description :

There is at least one open-source application from Mozilla.org
installed on the remote Windows host. 

See also :

http://www.mozilla.org/products/

Risk factor : 

None";


if (description) {
  script_id(20862);
  script_version("$Revision: 1.9 $");

  script_name(english:"Mozilla.org Application Detection");
  script_summary(english:"Checks for various applications from Mozilla.org"); 
 
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

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


# Determine if various applications are installed.
exes = make_array();
# - Mozilla Browser.
key = "SOFTWARE\mozilla.org\Mozilla";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  item = RegQueryValue(handle:key_h, item:"CurrentVersion");
  if (!isnull(item)) {
    ver = item[1];

    key2 = "SOFTWARE\mozilla.org\Mozilla\" + ver + "\Main";
    key_h2 = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h2)) {
      item = RegQueryValue(handle:key_h2, item:"PathToExe");
      if (!isnull(item)) exes[item[1]] = "Mozilla Browser";
      RegCloseKey(handle:key_h2);
    }
  }
  RegCloseKey(handle:key_h);
}
# - Mozilla Firefox.
key = "SOFTWARE\Mozilla\Mozilla Firefox";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  item = RegQueryValue(handle:key_h, item:"CurrentVersion");
  if (!isnull(item)) {
    ver = item[1];

    key2 = "SOFTWARE\Mozilla\Mozilla Firefox\" + ver + "\Main";
    key_h2 = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h2)) {
      item = RegQueryValue(handle:key_h2, item:"PathToExe");
      if (!isnull(item)) exes[item[1]] = "Mozilla Firefox";
      RegCloseKey(handle:key_h2);
    }
  }
  RegCloseKey(handle:key_h);
}
# nb: this is for older versions of Firefox (eg, 0.8).
else {
  key = "SOFTWARE\mozilla.org\Mozilla Firefox";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h)) {
    item = RegQueryValue(handle:key_h, item:"CurrentVersion");
    if (!isnull(item)) {
      ver = item[1];

      key2 = "SOFTWARE\mozilla.org\Mozilla Firefox\" + ver + "\Main";
      key_h2 = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key_h2)) {
        item = RegQueryValue(handle:key_h2, item:"PathToExe");
        if (!isnull(item)) exes[item[1]] = "Mozilla Firefox";
        RegCloseKey(handle:key_h2);
      }
    }
    RegCloseKey(handle:key_h);
  }
}
# - Mozilla Thunderbird.
key = "SOFTWARE\Mozilla\Mozilla Thunderbird";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  item = RegQueryValue(handle:key_h, item:"CurrentVersion");
  if (!isnull(item)) {
    ver = item[1];

    key2 = "SOFTWARE\Mozilla\Mozilla Thunderbird\" + ver + "\Main";
    key_h2 = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h2)) {
      item = RegQueryValue(handle:key_h2, item:"PathToExe");
      if (!isnull(item)) exes[item[1]] = "Mozilla Thunderbird";
      RegCloseKey(handle:key_h2);
    }
  }
  RegCloseKey(handle:key_h);
}
# - SeaMonkey.
key = "SOFTWARE\mozilla.org\SeaMonkey";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  item = RegQueryValue(handle:key_h, item:"CurrentVersion");
  if (!isnull(item)) {
    ver = item[1];

    key2 = "SOFTWARE\mozilla.org\SeaMonkey\" + ver + "\Main";
    key_h2 = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h2)) {
      item = RegQueryValue(handle:key_h2, item:"PathToExe");
      if (!isnull(item)) exes[item[1]] = "SeaMonkey";
      RegCloseKey(handle:key_h2);
    }
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


# Determine the version of each app from each executable itself.
info = "";
foreach exe (keys(exes))
{
  # Determine its version from the executable itself.
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exe);
  exe2 =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exe);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1);
  }

  fh = CreateFile(
    file:exe2,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (!isnull(fh))
  {
    ver = NULL;
    ret = GetFileVersionEx(handle:fh);
    CloseFile(handle:fh);
    if (
      !isnull(ret) &&
      !isnull(ret['dwProductVersionMS']) &&
      !isnull(ret['dwProductVersionLS'])
    )
    {
      ver = string(
        ret['dwProductVersionMS'] >>> 16, ".",
        ret['dwProductVersionMS'] & 0xFFFF, ".",
        ret['dwProductVersionLS'] >>> 16, ".",
        ret['dwProductVersionLS'] & 0xFFFF
      );

      prod = exes[exe];
      if (prod)
      {
        if (prod == "Mozilla Browser") kb_name = "Mozilla/Version";
        else kb_name = str_replace(find:" ", replace:"/", string:string(prod, "/Version"));

        set_kb_item(name:kb_name, value:ver);
        info += strcat(" - ", prod, " version ", ver, ' is installed as\n   ', exe, '\n\n');
      }
    }
  }
}


if (info) {
  report = strcat(
    desc,
    '\n\n',
    'Plugin output :\n',
    '\n',
    info
  );
  security_note(port:kb_smb_transport(), data:report);
}


# Clean up.
NetUseDel();
