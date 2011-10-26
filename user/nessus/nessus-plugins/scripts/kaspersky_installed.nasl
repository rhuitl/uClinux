#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote host has an anti-virus software package installed on it. 

Description :

The remote host is running Kaspersky Anti-Virus, a commercial anti-
virus software package for Windows. 

See also :

http://www.kaspersky.com/

Risk factor :

None";


if (description) {
  script_id(20284);
  script_version("$Revision: 1.126 $");

  script_name(english:"Kaspersky Anti-Virus Check");
  script_summary(english:"Checks for Kaspersky Anti-Virus");
 
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access", "SMB/transport");
  script_require_ports(139, 445);

  exit(0);
}


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
#
# - KAV Personal / KAV Personal Pro
prod++;
prod_subkeys[prod] = "KasperskyLab\InstalledProducts\Kaspersky Anti-Virus Personal";
name_subkeys[prod] = "Name";
path_subkeys[prod] = "Folder";
ver_subkeys[prod]  = "Version";
# - KAV for Workstations
prod++;
prod_subkeys[prod] = "Microsoft\Windows\CurrentVersion\Uninstall\{90467142-F6B5-48B5-9A46-AFE61C4598CA}";
name_subkeys[prod] = "DisplayName";
path_subkeys[prod] = "InstallLocation";
ver_subkeys[prod]  = "DisplayVersion";

foreach prod (keys(prod_subkeys)) {
  key = "SOFTWARE\" + prod_subkeys[prod];
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h)) {
    value = RegQueryValue(handle:key_h, item:name_subkeys[prod]);
    if (!isnull(value)) name = value[1];
    else name = NULL;

    value = RegQueryValue(handle:key_h, item:path_subkeys[prod]);
    if (!isnull(value)) path = ereg_replace(string:value[1], pattern:"\$", replace:"");

    value = RegQueryValue(handle:key_h, item:ver_subkeys[prod]);
    if (!isnull(value)) ver = value[1];

    RegCloseKey (handle:key_h);

    # We found a product so we're done.
    break;
  }
  else name = NULL;
}

if (isnull(name) || isnull(path) || isnull(ver)) {
  NetUseDel();
  exit(0);  
}
set_kb_item(name:"Antivirus/Kaspersky/installed", value:TRUE);
set_kb_item(name:"Antivirus/Kaspersky/" + name, value:ver + " in " + path);


# Pull info about the virus signatures from KAVSET.XML.
sigs_target = "unknown";
# nb: for some products, we can get the file's location from a registry entry.
key = "SOFTWARE\KasperskyLab\Components\10a\LastSet";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:"Directory");
  if (!isnull(value)) sig_path = ereg_replace(string:value[1], pattern:"\$", replace:"");

  NetUseDel(close:FALSE);
}
# nb: others require we extract it from SS_PRODINFO.xml.
if (isnull(sig_path)) {
  # - find SS_PRODINFO.xml.
  key = "SOFTWARE\KasperskyLab\Components\34";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h)) {
    value = RegQueryValue(handle:key_h, item:"SS_PRODINFO");
    if (!isnull(value)) prodinfo = ereg_replace(string:value[1], pattern:"\$", replace:"");

    NetUseDel(close:FALSE);
  }
  RegCloseKey(handle:hklm);
  # - read SS_PRODINFO.xml to get the BaseFolder setting.
  if (prodinfo) {
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:prodinfo);
    prodinfo_file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:prodinfo);

    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (rc == 1) {
      fh = CreateFile(
        file:prodinfo_file,
        desired_access:GENERIC_READ,
        file_attributes:FILE_ATTRIBUTE_NORMAL,
        share_mode:FILE_SHARE_READ,
        create_disposition:OPEN_EXISTING
      );
      if (!isnull(fh)) {
        contents = ReadFile(handle:fh, offset:0, length:10240);
        contents = str_replace(string:contents, find:raw_string(0x00), replace:"");

        # Isolate the base folder path.
        sig_path = strstr(contents, "BaseFolder");
        if (sig_path) {
          len = ord(sig_path[11]);
          if (sig_path) sig_path = substr(sig_path, 12, 12+len-1);
        }
      
        CloseFile(handle:fh);
      }

      NetUseDel(close:FALSE);
    }
  }
}
RegCloseKey(handle:hklm);


if (sig_path) {
  # Read signature date from the file KAVSET.XML.
  # 
  # nb: this is stored typically in a hidden directory, in case one's
  #     simply looking for it.
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sig_path);
  xml_file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\kavset.xml", string:sig_path);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc == 1) {
    fh = CreateFile(
      file:xml_file,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh)) {
      xml = ReadFile(handle:fh, offset:0, length:256);

      # Get the date from the update_date XML block.
      update_date = strstr(xml, "Updater/update_date");
      if (update_date) update_date = update_date - strstr(update_date, '" />');
      if (update_date) update_date = strstr(update_date, 'Value="');
      if (update_date) update_date = update_date - 'Value="';      
      if (!isnull(update_date) && update_date =~ "^[0-9]+ [0-9]+$") {
        day   = substr(update_date, 0, 1);
        month = substr(update_date, 2, 3);
        year  = substr(update_date, 4, 7);
        sigs_target = string(month, "/", day, "/", year);
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
report = "Kaspersky Anti-Virus is installed on the remote host :

  Product Name:      " + name + " 
  Version:           " + ver + "
  Installation Path: " + path + "
  Virus signatures:  " + sigs_target + "

";

# - sigs out-of-date?
sigs_vendor_yyyymmdd = "20061030";
if (sigs_target =~ "[0-9][0-9]/[0-9][0-9]/[0-9][0-9][0-9][0-9]") {
  a = split(sigs_target, sep:"/", keep:0);
  sigs_target_yyyymmdd = string(a[2], a[0], a[1]);

  if (int(sigs_target_yyyymmdd) < ( int(sigs_vendor_yyyymmdd) - 1 ) ) {
    sigs_vendor_mmddyyyy = string(
      substr(sigs_vendor_yyyymmdd, 4, 5), 
      "/",
      substr(sigs_vendor_yyyymmdd, 6, 7), 
      "/",
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
    "Kaspersky Anti-Virus Service" >!< services &&
    "kavsvc" >!< services
  )
) {
  report += "The remote Kaspersky Anti-Virus service is not running.

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
  set_kb_item (name:"Antivirus/Kaspersky/description", value:report);
}
