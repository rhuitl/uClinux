#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote Windows host contains an application that is affected by an
information disclosure vulnerability. 

Description :

Adobe Contribute Publishing Server, a web publishing management
application, is installed on the remote Windows host. 

The version of Contribute Publishing Server on the remote host logged
a copy of the password specified for the administrator as part of the
installation process.  A local user may be able to leverage this flaw
to gain administrative access to the affected application and
potentially other resources. 

See also :

http://www.adobe.com/support/security/bulletins/apsb06-15.html

Solution :

Change the application's administrator password and remove the
installation log as described in the vendor advisory referenced above. 

Risk factor :

Low / CVSS Base Score : 1.6
(AV:L/AC:L/Au:NR/C:P/I:N/A:N/B:N)";


if (description)
{
  script_id(22540);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-5199");
  script_bugtraq_id(20439);

  script_name(english:"Adobe Contribute Publishing Server Administrator Password Disclosure");
  script_summary(english:"Checks for administrator password in Adobe Contribute Publishing Server installation log");
 
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
include("smb_hotfixes.inc");


# Exit unless we're paranoid because we don't have a good way to validate
# the password we find.
if (report_paranoia < 2) exit(0);


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
name = kb_smb_name();
port = kb_smb_transport();
if (!get_port_state(port)) exit(0);
login = kb_smb_login();
pass = kb_smb_password();
domain = kb_smb_domain();


# Connect to the remote registry.
soc = open_sock_tcp(port);
if (!soc) exit(0);
session_init(socket:soc, hostname:name);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) exit(0);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Check whether it's installed.
key = "SOFTWARE\Macromedia\Macromedia Contribute Publishing Server";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
path = NULL;
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Installation_Dir");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


# If it is, try to grab the admin password.
admin_pw = NULL;
if (!isnull(path))
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
  file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\UninstallerData\installvariables.properties", string:path);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(0);
  }

  fh = CreateFile(
    file               : file,
    desired_access     : GENERIC_READ,
    file_attributes    : FILE_ATTRIBUTE_NORMAL,
    share_mode         : FILE_SHARE_READ,
    create_disposition : OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    fsize = GetFileSize(handle:fh);
    if (fsize > 10240) fsize = 10240;
    if (fsize)
    {
      data = ReadFile(handle:fh, length:fsize, offset:0);
      if (data && '\nCONFIRM_ADMIN_PASSWORD=' >< data)
      {
        admin_pw = strstr(data, '\nCONFIRM_ADMIN_PASSWORD=') - '\nCONFIRM_ADMIN_PASSWORD=';
        admin_pw = admin_pw - strstr(admin_pw, '\n');
        if (admin_pw) admin_pw = chomp(admin_pw);
      }
    }
  }
}


# There's a problem if we have a password.
if (admin_pw)
{
  if (report_verbosity)
    report = strcat(
      desc,
      '\n\n',
      'Plugin output :\n',
      '\n',
      'Nessus was able to read the following password from the installation\n',
      'log but has not tried to validate it :\n',
      '\n',
      '  ', admin_pw
    );
  else report = desc;

  security_note(port:kb_smb_transport(), data:report);
}


# Clean up.
NetUseDel();
