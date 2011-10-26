#
# (C) Josh Zlatin-Amishav and Tenable Network Security
# GPLv2
#
# Tenable grants a special exception for this plugin to use the library 
# 'smb_func.inc'. This exception does not apply to any modified version of 
# this plugin.
#

 desc = "
Synopsis :

The remote Windows host has a spyware detection program installed on it.

Description :

The remote Windows host is running Spybot Search & Destroy, a privacy 
enhancing application that can detect and remove spyware of different 
kinds from your computer.

See also :

http://www.safer-networking.org/

Risk factor :

None";

if(description)
{
 script_id(21162);
 script_version("$Revision: 1.28 $");

 name["english"] = "Spybot Search & Destroy Detection";
 script_name(english:name["english"]);
 
 script_description(english:desc);
 
 summary["english"] = "Checks whether Spybot Search & Destroy is installed";

 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Josh Zlatin-Amishav and Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/transport"); 
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");


name 	= kb_smb_name();
login	= kb_smb_login();
pass  	= kb_smb_password();
domain	= kb_smb_domain();
port    = kb_smb_transport();

if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);
if(!soc)exit(1);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) 
{
  NetUseDel();
  exit(0);
}


# First find where the executable is installed on the remote host
# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) 
{
  if (log_verbosity > 1) debug_print("can't connect to the remote registry!", level:0);
  NetUseDel();
  exit(0);
}


# Determine where Spybot S&D is installed
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Spybot - Search & Destroy_is1";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:"Inno Setup: App Path");
  if (!isnull(value)) path = value[1];
  else path = NULL;
  
  RegCloseKey(handle:key_h);
}
else path = NULL;
RegCloseKey(handle:hklm);

if (isnull(path)) {
  NetUseDel();
  exit(0);
}


# Get the file version / latest sigs.
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
exe = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\SpybotSD.exe", string:path);
rules = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Updates\downloaded.ini", string:path);
  
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (r != 1) {
  if (log_verbosity > 1) debug_print("can't connect to the remote share (", r, ")!", level:0);
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (isnull(fh))
{
  if (log_verbosity > 1) debug_print("can't open ", exe, "!", level:0);
  NetUseDel();
  exit(0);
}

version = GetFileVersion(handle:fh);
CloseFile(handle:fh);
if (isnull(version))
{
  if (log_verbosity > 1) debug_print("can't get file version for ", exe, "!", level:0);
  NetUseDel();
  exit(0);
}

ver = string(version[0], ".", version[1], ".", version[2], ".", version[3]);
set_kb_item(name:"SMB/SpybotSD/version", value:ver);


# Get release date info about the detection rules (includes.zip)
fh = CreateFile(
  file:rules,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (isnull(fh))
{
  if (log_verbosity > 1) debug_print("can't open ", rules, "!", level:0);
  NetUseDel();
  exit(0);
}

contents = ReadFile(handle:fh, offset:0, length:85);
CloseFile(handle:fh);
if (isnull(contents))
{
  if (log_verbosity > 1) debug_print("can't read ", rules, "!", level:0);
  NetUseDel();
  exit(0);
}
NetUseDel();

sigs_target = strstr(contents, "ReleaseDate=");
if (strlen(sigs_target) >= 22) sigs_target = substr(sigs_target, 12, 22);
if (isnull(sigs_target)) sigs_target = "n/a";

if (sigs_target =~ "[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]") {
  a = split(sigs_target, sep:"-", keep:0);
  sigs_target_yyyymmdd = string(a[0], a[1], a[2]);
  sigs_target_mmddyyyy = string(a[1], "/", a[2], "/", a[0]);
} 
else sigs_target_mmddyyyy = "n/a";


sigs_vendor_yyyymmdd = "";
sigs_vendor_mmddyyyy = string(
  substr(sigs_vendor_yyyymmdd, 4, 5),
  "/",
  substr(sigs_vendor_yyyymmdd, 6, 7),
  "/",
  substr(sigs_vendor_yyyymmdd, 0, 3)
);

# Generate report.
report = string(
  desc,
  "\n\n",
  "Plugin output :\n\n",
  "  Version    : ", ver, "\n",
  "  Signatures : ", sigs_target_mmddyyyy
);

if (sigs_target == "n/a")
{
    report = string(
      report,
      "\n\n",
      "The remote host has never updated its Spybot S&D detection rule\n",
      "signatures. The latest version is ", sigs_vendor_mmddyyyy, ". As a result, the\n",
      "remote host might contain malware."
    );
    security_hole(port:kb_smb_transport(), data:report);
}
else if (sigs_target_yyyymmdd)
{
  if (int(sigs_target_yyyymmdd) < int(sigs_vendor_yyyymmdd))
  {
    report = string(
      report,
      "\n\n",
      "The remote host has an out-dated version of the Spybot S&D\n",
      "detection rule signatures; the most recent set is ", sigs_vendor_mmddyyyy, ".\n",
      "As a result, the remote host might contain malware."
    );
    security_hole(port:kb_smb_transport(), data:report);
  }	 
  else security_note(port:kb_smb_transport(), data:report);
}
