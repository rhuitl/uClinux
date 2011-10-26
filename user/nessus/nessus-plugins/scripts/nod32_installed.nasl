#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote host has an anti-virus software package installed on it. 

Description :

The remote host is running the NOD32 Antivirus System, a commercial
anti-virus software package for Windows. 

See also :

http://www.nod32.com/

Risk factor :

None";


if (description) {
  script_id(21608);
  script_version("$Revision: 1.26 $");

  script_name(english:"NOD32 Antivirus System Check");
  script_summary(english:"Checks for NOD32 Antivirus System");
 
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

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
key = "SOFTWARE\Eset\Nod\CurrentVersion\Info";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:"InstallDir");
  if (!isnull(value)) path = value[1];
  else path = NULL;

  # Sig date is stored in the registry.
  value = RegQueryValue(handle:key_h, item:"CurrentVersion");
  if (!isnull(value)) 
    sigs_target = ereg_replace(pattern:".*\((.+)\)", string:value[1], replace:"\1");
  else
    sigs_target = NULL;

  RegCloseKey (handle:key_h);
}
RegCloseKey(handle:hklm);


# If it is, get the application's version number.
if (!isnull(path))
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
  exe =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\nod32.exe", string:path);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc == 1)
  {
    fh = CreateFile(
      file:exe,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh))
    {
      version = GetFileVersion(handle:fh);
      ver = string(version[0], ".", version[1], ".", version[2], ".", version[3]);
      CloseFile(handle:fh);
    }
  }
}
NetUseDel();


if (isnull(path) || isnull(sigs_target) || isnull(ver)) exit(0);  
set_kb_item(name:"Antivirus/NOD32/installed", value:TRUE);
set_kb_item(name:"Antivirus/NOD32/version", value:ver);
set_kb_item(name:"Antivirus/NOD32/path", value:path);


# Generate report
trouble = 0;

# - general info.
report = "The NOD32 Antivirus System is installed on the remote host :

  Version:           " + ver + "
  Installation Path: " + path + "
  Virus signatures:  " + sigs_target + "

";

# - sigs out-of-date?
sigs_vendor_yyyymmdd = "20061027";
if (sigs_target =~ "^2[0-9][0-9][0-9][01][0-9][0-3][0-9]")
{
  sigs_target_yyyymmdd = sigs_target;

  if (int(sigs_target_yyyymmdd) < int(sigs_vendor_yyyymmdd)) {
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
    "NOD32 Kernel Service" >!< services &&
    "NOD32km" >!< services
  )
) {
  report += "The remote NOD32 service is not running.

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
  set_kb_item (name:"Antivirus/NOD32/description", value:report);
}
