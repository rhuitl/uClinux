#
#  (C) Tenable Network Security
#


 desc = "
Synopsis :

The remote Windows host has an ActiveX control that is affected by a
buffer overflow vulnerability. 

Description :

The remote host contains an ActiveX control from AOL called YPG
Picture Finder Tool.  It was distributed along with various versions
of AOL's client software and from the You've Got Pictures web site
prior to 2004.  The 'YGPPicFinder.DLL' component of this control fails
to limit the amount of user-supplied data copied to a finite buffer. 
This can be exploited using, say, a specially-crafted web page to
overflow the buffer, crash the application using the control
(typically Internet Explorer), and possibly execute arbitrary code
subject to the user's privileges. 

See also :

http://www.kb.cert.org/vuls/id/715730
http://download.newaol.com/security/YGPClean.exe

Solution :

Download and run AOL's removal tool. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description) {
  script_id(20737);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-0316");
  script_bugtraq_id(16262);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"22486");
  }

  script_name(english:"AOL You've Got Pictures ActiveX Control Overflow Vulnerability");
  script_summary(english:"Checks for overflow vulnerability in AOL You've Got Pictures ActiveX control"); 
 
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


name = NULL;
# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  NetUseDel();
  exit(0);
}


# Determine if the control is installed.
clid = "B33CCD56-0909-42C9-8A88-8976F66B8BF2";
key = "SOFTWARE\Classes\CLSID\{" + clid +  "}";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) 
    name = value[1];
  else
    name = NULL;
 
  RegCloseKey(handle:key_h);
}
else name = NULL;


# If it is...
if (name) {
  # Determine where it's installed.
  key = "SOFTWARE\Classes\CLSID\{" + clid + "}\InprocServer32";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h)) {
    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value)) {
      if (value[1] =~ "YGPPicFinder") file = value[1];
    }
    RegCloseKey(handle:key_h);
  }

  # Generate the report.
  if (file ) {
    report = desc + string(
      "\n\n",
      "Plugin output :\n",
      "\n",
      "The YPG Picture Finder Tool ActiveX control is installed as \n",
      "\n",
      "  ") + file + '\n';
      security_warning(port:port, data:report);
  }

}


# Clean up.
RegCloseKey(handle:hklm);
NetUseDel();
