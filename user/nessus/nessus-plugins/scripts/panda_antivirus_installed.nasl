#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote host has an anti-virus software installed on it.

Description :

The remote host is running Panda Antivirus, a commercial anti-virus 
software package for Windows.

See also :

http://www.pandasoftware.com/

Risk factor :

None";


if (description) {
  script_id(20283);
  script_version("$Revision: 1.126 $");

  script_name(english:"Panda Antivirus Check");
  script_summary(english:"Checks for Panda Antivirus");
 
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access", "SMB/transport");
  script_require_ports(139, 445);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("smb_func.inc");


# Connect to the remote registry.
if (!get_kb_item("SMB/registry_full_access")) exit(0);


name    = kb_smb_name();
if (!name) exit(0);
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();
port    = kb_smb_transport();
if (!port) port = 139;
if (!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
  exit(0);
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  NetUseDel();
  exit(0);
}


# Check if the software is installed.
# - for Panda Titanium / TruProtect.
prod++;
prod_subkeys[prod] = "Panda Antivirus Lite";
name_subkeys[prod] = "PRODUCT";
path_subkeys[prod] = "DIR";
ver_subkeys[prod]  = "VERSION";
# - for Platinum.
prod++;
prod_subkeys[prod] = "Setup";
name_subkeys[prod] = "PRODUCTNAME";
path_subkeys[prod] = "PATH";
ver_subkeys[prod]  = "NORMAL";

foreach prod (keys(prod_subkeys)) {
  key = string("SOFTWARE\\Panda Software\\", prod_subkeys[prod]);
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h)) {
    value = RegQueryValue(handle:key_h, item:name_subkeys[prod]);
    if (!isnull(value)) name = value[1];
    else name = NULL;

    value = RegQueryValue(handle:key_h, item:path_subkeys[prod]);
    if (!isnull(value)) {
      path = ereg_replace(string:value[1], pattern:"\$", replace:"");
    }

    value = RegQueryValue(handle:key_h, item:ver_subkeys[prod]);
    if (!isnull(value)) { 
      ver = value[1];
    }

    RegCloseKey (handle:key_h);

    # We found a product so we're done.
    break;
  }
  else name = NULL;
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if (isnull(name) || isnull(path) || isnull(ver)) {
  NetUseDel();
  exit(0);  
}
set_kb_item(name:"Antivirus/Panda/installed", value:TRUE);
set_kb_item(name:"Antivirus/Panda/" + name, value:ver + " in " + path);


# Get info about the virus signatures.
sigs_target = "unknown";
if (!isnull(path)) {
  # Read signature date from the file PAV.SIG.
  #
  # nb: it's also encoded as year-day-month in the file in 
  #     bytes 0x65-0x68; eg, d5 07 11 0a => 2005-Oct-17
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
  sigfile =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\pav.sig", string:path);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc == 1) {
    fh = CreateFile(
      file:sigfile,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh)) {
      hex_date = ReadFile(handle:fh, offset:0x65, length:4);

      if (!isnull(hex_date)) {
        set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);
        year  = getword(blob:hex_date, pos:0);
        day   = getbyte(blob:hex_date, pos:2);
        if (strlen(day) == 1) day = string("0", day);
        month = getbyte(blob:hex_date, pos:3);
        if (strlen(month) == 1) month = string("0", month);
        sigs_target = string(month, "-", day, "-", year);
      }

      CloseFile(handle:fh);
    }

    NetUseDel(close:FALSE);
  }
}
NetUseDel();


# Generate report
trouble = 0;

# - general info.
report = "Panda Antivirus is installed on the remote host :

  Product Name:      " + name + " 
  Version:           " + ver + "
  Installation Path: " + path + "
  Virus signatures:  " + sigs_target + "

";

# - sigs out-of-date?
sigs_vendor_yyyymmdd = "20061029";
if (sigs_target =~ "[0-9][0-9]-[0-9][0-9]-[0-9][0-9][0-9][0-9]") {
  a = split(sigs_target, sep:"-", keep:0);
  sigs_target_yyyymmdd = string(a[2], a[0], a[1]);

  if (int(sigs_target_yyyymmdd) < ( int(sigs_vendor_yyyymmdd) - 1 )) {
    sigs_vendor_mmddyyyy = string(
      substr(sigs_vendor_yyyymmdd, 4, 5), 
      "-",
      substr(sigs_vendor_yyyymmdd, 6, 7), 
      "-",
      substr(sigs_vendor_yyyymmdd, 0, 3)
    );

    report += "The virus signatures on the remote host are out-of-date - the last 
known update from the vendor is " + sigs_vendor_mmddyyyy + "

";
    trouble++;
  }
}


# - services running.
services = get_kb_item("SMB/svcs");
if (
  services &&
  (
    # Panda Antivirus Titanium
    "Panda anti-virus service" >!< services &&
    # Panda TruPrevent
    "Panda TPSrv" >!< services
  )
) {
  report += "The remote Panda AntiVirus service is not running.

";
  trouble++;
}


if (trouble) report += "As a result, the remote host might be infected by viruses.";

if (trouble) {
  report = string(
    desc,
    "\n\n",
    "Plugin output :\n",
    "\n",
    report
  );

  security_hole(port:port, data:report);
}
else {
  # nb: antivirus.nasl uses this in its own report.
  set_kb_item (name:"Antivirus/Panda/description", value:report);
}
