#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22035);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-3453");
  script_bugtraq_id(18943);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"27156");

  script_name(english:"Adobe Acrobat < 6.0.5");
  script_summary(english:"Checks version of Adobe Acrobat");

  desc = "
Synopsis :

The remote Windows host contains an application that is affected by several
issues. 

Description :

The version of Adobe Acrobat installed on the remote host is earlier
than 6.0.5 and is reportedly affected by a buffer overflow that
may be triggered when distilling a specially-crafted file to PDF.

See also :

http://www.adobe.com/support/security/bulletins/apsb06-09.html

Solution : 

Upgrade to Adobe Acrobat 6.0.5 or later. 

Risk factor : 

Medium / CVSS Base Score : 5.5
(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)";

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


# Determine where it's installed.
key = "SOFTWARE\Classes\Software\Adobe\Acrobat\Distiller";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
dll = NULL;
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Exe");
  if (!isnull(value)) dll = value[1];

  RegCloseKey (handle:key_h);
}
RegCloseKey(handle:hklm);


# If it is...
if (dll)
{
  # Determine its version from the executable itself.
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dll);
  dll2 =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dll);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(0);
  }

  fh = CreateFile(
    file:dll2,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  ver = NULL;
  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);
  }

  # There's a problem if the version is < 6.0.5.
  if (!isnull(ver))
  {
    if (
      ver[0] < 6 ||
      (ver[0] == 6 && ver[1] == 0 && ver[2] < 5)
    )
    {
      if (report_verbosity < 1) report = desc;
      else 
      {
        version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
        report = string(
          desc,
          "\n\n",
          "Plugin output :\n",
          "\n",
          "Version ", version, " of the Adobe Acrobat distiller is installed as :\n",
          "  ", dll, "\n"
        );
      }
      security_warning(port:port, data:report);
    }
  }
}


# Clean up.
NetUseDel();
