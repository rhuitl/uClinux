#
#  (C) Tenable Network Security
#


 desc = "
Synopsis :

The remote Windows host has an ActiveX control that is prone to remote
code execution. 

Description :

The remote host contains an ActiveX control from First4Internet called
CodeSupport.  This control was likely installed by requesting an
uninstaller for Sony's XCP digital rights management software. 

CodeSupport is marked as safe for scripting and makes several methods
available for any web page to use.  Should a user visit a
maliciously-crafted website, this would allow that website to execute
arbitrary code on the remote host. 

See also :

http://hack.fi/~muzzy/sony-drm/
http://www.freedom-to-tinker.com/?p=927

Solution :

On the affected host, locate the file 'codesupport.ocx', 
run the following DOS commands, and reboot.

  regsvr32 /u '%windir%\downloaded program files\codesupport.ocx'
  cmd /k del '%windir%\downloaded program files\codesupport.*'

assuming it's located in '%windir%\downloaded program files'.

Risk factor : 

Medium / CVSS Base Score : 6
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(20220);
  script_version("$Revision: 1.2 $");

  script_name(english:"CodeSupport ActiveX Remote Code Execution Vulnerability");
  script_summary(english:"Checks for remote code execution vulnerability in CodeSupport ActiveX control"); 
 
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");

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
  exit(1);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  NetUseDel();
  exit(1);
}


# Determine if the control is installed.
key = "SOFTWARE\Classes\CLSID\{4EA7C4C5-C5C0-4F5C-A008-8293505F71CC}";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) name = value[1];
  else name = NULL;

  RegCloseKey(handle:key_h);
}
else name = NULL;


# If it is...
if (name && "CodeSupport Control" >< name) {
  # Determine where it's installed.
  key = "SOFTWARE\Classes\CLSID\{4EA7C4C5-C5C0-4F5C-A008-8293505F71CC}\InprocServer32";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h)) {
    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value)) {
      file = value[1];
    }
    RegCloseKey(handle:key_h);
  }

  # And its version.
  #
  # nb: no word on whether only certain versions of the control are 
  #     affected so treat them all as bad.
  key = "SOFTWARE\Classes\CLSID\{4EA7C4C5-C5C0-4F5C-A008-8293505F71CC}\Version";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h)) {
    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value)) {
      ver = value[1];
    }
    RegCloseKey(handle:key_h);
  }

  # Generate the report.
  if (file && ver && report_verbosity > 0) {
    report = desc + string(
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Version ", ver, " of the control is installed as \n",
      "\n",
      "  ", file, "\n"
    );
  }
  else report = desc;

  security_warning(port:port, data:report);
}


# Clean up.
RegCloseKey(handle:hklm);
NetUseDel();
