#
#  (C) Tenable Network Security
#


if (description)
{
  script_id(22003);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2006-3268");
  script_bugtraq_id(18716);

  script_name(english:"GroupWise Windows Client API Unauthorized Email Access Vulnerability");
  script_summary(english:"Check the version of GroupWise client"); 
 
 desc = "
Synopsis :

The remote Windows host contains a mail client that may allow
unauthorized access to email messages. 

Description :

The remote host is running GroupWise, an enterprise-class
collaboration application from Novell. 

The version of GroupWise installed on the remote host contains a flaw
in the client API that may allow a user to bypass security controls
and gain access to non-authorized email within the same authenticated
post office. 

See also :

http://www.securityfocus.com/advisories/10778

Solution :

Upgrade to GroupWise 6.5 SP6 Update 1 / 7 SP1 or later. 

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";
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


# Get some info about the install.
exe = NULL;
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\GrpWise.exe";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(item)) exe = item[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


# If it is...
if (exe)
{
  # Determine its version from the executable itself.
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exe);
  exe =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exe);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
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
  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);
  }

  # There's a problem if the version is before 6.57.0.0 or 7.0.1.364.
  if (!isnull(ver))
  {
    if (
      ver[0] < 6 ||
      (ver[0] == 6 && ver[1] < 57) ||
      (
        ver[0] == 7 && ver[1] == 0 && 
          (
            ver[2] == 0 ||
            (ver[2] == 1 && ver[3] < 364)
          )
      )
    ) security_note(kb_smb_transport());
  }
}


# Clean up.
NetUseDel();
