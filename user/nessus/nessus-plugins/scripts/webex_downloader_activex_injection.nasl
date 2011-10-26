#
#  (C) Tenable Network Security
#


 desc = "
Synopsis :

The remote Windows host has an ActiveX control that allows for
arbitrary code execution. 

Description :

The Windows remote host contains the WebEx Downloader ActiveX control,
which is used when attending or hosting a meeting using WebEx, a
sharing and conferencing application for Windows. 

The version of this ActiveX control on the remote host reportedly
allows an attacker to deliver arbitrary components to the affected
host, which could later be executed subject to the privileges of the
current user. 

See also :

http://xforce.iss.net/xforce/alerts/id/226
http://www.zerodayinitiative.com/advisories/ZDI-06-021.html
http://www.webex.com/lp/security/ActiveAdv.html?TrackID=123456

Solution :

Upgrade to WebEx Downloader plugin 2.1.0.0 or later. 

Risk factor : 

Medium / CVSS Base Score : 4.6
(AV:R/AC:L/Au:NR/C:P/I:P/A:N/B:N)";


if (description)
{
  script_id(22047);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-3423");
  script_bugtraq_id(18860);
  if (defined_func("script_xref"))
  {
    script_xref(name:"OSVDB", value:"27039");
    script_xref(name:"OSVDB", value:"27040");
  }

  script_name(english:"WebEx Downloader ActiveX Control Injection Vulnerability");
  script_summary(english:"Checks version of the WebEx Downloader ActiveX control"); 
 
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


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
if (rc != 1)
{
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Check whether it's installed.
clid = "E06E2E99-0AA1-11D4-ABA6-0060082AA75C";
key = "SOFTWARE\Classes\CLSID\{" + clid +  "}\InprocServer32";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
file = NULL;
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) file = value[1];

  RegCloseKey(handle:key_h);
}


# If it is...
if (file)
{
  # Determine the version from the DLL itself.
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:file);
  dll =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:file);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(0);
  }

  fh = CreateFile(
    file:dll,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);
  }

  # There's a problem if the version number is < 2.1.0.0.
  if (
    !isnull(ver) &&
    (
      ver[0] < 2 ||
      (ver[1] == 2 && ver[2] < 1)
    )
  )
  {
    version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Version ", version, " of the control is installed as \n",
      "\n",
      "  ", file, "\n",
      "\n"
    );
    security_warning(port:port, data:report);
  }
}


# Clean up.
RegCloseKey(handle:hklm);
NetUseDel();

