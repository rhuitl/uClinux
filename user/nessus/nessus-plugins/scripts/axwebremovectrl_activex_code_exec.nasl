#
#  (C) Tenable Network Security
#


 desc = "
Synopsis :

The remote Windows host has an ActiveX control that is prone to remote
code execution. 

Description :

The remote host contains an ActiveX control from SunnComm called
AxWebRemoveCtrl.  This control was likely installed by requesting an
uninstaller for SunnComm's MediaMax digital rights management software
used, for example, on select Sony CDs. 

By design, AxWebRemoveCtrl allows any web site to cause the control to
download and execute code from an arbitrary URL.  Should a user visit
a maliciously-crafted website, this would allow that website to
execute arbitrary code on the remote host. 

See also :

http://www.freedom-to-tinker.com/?p=931
http://www.sunncomm.com/support/faq/

Solution :

On the affected host, remove the file 'AxWebRemoveCtrl.ocx', and
reboot. 

Risk factor : 

Medium / CVSS Base Score : 6
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(20297);
  script_version("$Revision: 1.3 $");

  script_name(english:"AxWebRemoveCtrl ActiveX Remote Code Execution Vulnerability");
  script_summary(english:"Checks for remote code execution vulnerability in AxWebRemoveCtrl ActiveX control"); 
 
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
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  NetUseDel();
  exit(0);
}


# Determine if the control is installed.
clid = "1F1EB85B-0FE9-401D-BC53-10803CF880A7";
key = "SOFTWARE\Classes\CLSID\{" + clid +  "}";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) name = value[1];
  else name = NULL;

  RegCloseKey(handle:key_h);
}
else name = NULL;


# If it is...
if (name && "AxWebRemoveCtrl" >< name) {
  # Determine where it's installed.
  key = "SOFTWARE\Classes\CLSID\{" + clid + "}\InprocServer32";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h)) {
    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value)) {
      file = value[1];
    }
    RegCloseKey(handle:key_h);
  }

  # Generate the report.
  if (file && report_verbosity > 0) {
    report = desc + string(
      "\n\n",
      "Plugin output :\n",
      "\n",
      "The AxWebRemoveCtrl ActiveX control is installed as \n",
      "\n",
      "  ") + file + '\n';
  }
  else report = desc;

  security_warning(port:port, data:report);
}


# Clean up.
RegCloseKey(handle:hklm);
NetUseDel();
