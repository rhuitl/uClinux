#
#  (C) Tenable Network Security
#


 desc = "
Synopsis :

The remote Windows host has a rootkit installed on it. 

Description :

First 4 Internet's Extended Copy Protection (XCP) digital rights
management software is installed on the remote Windows host.  While it
is not malicious per se, the software hides files, processes, and
registry keys / values from ordinary inspection, which has been
exploited by several viruses to hide from anti-virus software. 

See also :

http://www.sysinternals.com/blog/2005/10/sony-rootkits-and-digital-rights.html
http://www.sysinternals.com/blog/2005/11/sony-no-more-rootkit-for-now.html
http://www.sophos.com/pressoffice/news/articles/2005/11/stinxe.html

Solution :

On the affected host, run the DOS command 'cmd /k sc delete $sys$aries'
to deactivate the software and reboot. 

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:L/AC:H/Au:NR/C:C/A:C/I:C/B:N)";


if (description) {
  script_id(20212);
  script_version("$Revision: 1.2 $");

  script_name(english:"XCP DRM Software Detection");
  script_summary(english:"Checks whether XCP DRM Software is installed"); 
 
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/svcs", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");


# Check whether either of the two services XCP installs are running.
services = get_kb_item("SMB/svcs");
if (
  services &&
  (
    "XCP CD Proxy" >< services ||
    "Plug and Play Device Manager" >< services
  )
) {
  # Identify the location of the file cloaking device driver.
  winroot = hotfix_get_systemroot();
  if (!winroot) exit(1);
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:winroot);
  file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\System32\$sys$filesystem\aries.sys", string:winroot);

  # Connect to the appropriate share.
  name    =  kb_smb_name();
  port    =  kb_smb_transport();
  if (!get_port_state(port)) exit(1);
  login   =  kb_smb_login();
  pass    =  kb_smb_password();
  domain  =  kb_smb_domain();

  soc = open_sock_tcp(port);
  if (!soc) exit(1);

  session_init(socket:soc, hostname:name);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1) {
    if (log_verbosity > 1) debug_print("can't connect to the remote share (rc)!", level:0);
    NetUseDel();
    exit(1);
  }

  # Try to open one of the driver's files.
  fh = CreateFile(
    file:file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  # There's a problem if the file exists.
  if (!isnull(fh)) {
    security_warning(port);
    CloseFile(handle:fh);
  }
  NetUseDel();
}
