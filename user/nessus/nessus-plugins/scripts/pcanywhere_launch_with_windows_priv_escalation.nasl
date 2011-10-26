#
# (C) Tenable Network Security
#


if (description) {
  script_id(20743);
  script_version("$Revision: 1.1 $");

  script_cve_id("CVE-2005-1970");
  script_bugtraq_id(13933);

  script_name(english:"pcAnywhere Launch with Windows Privilege Escalation Vulnerability");
  script_summary(english:"Checks for Launch with Windows privilege escalation vulnerability in pcAnywhere");

  desc = "
Synopsis :

The remote control software on the remote host is affected by a local
privilege escalation flaw. 

Description :

The remote host is running pcAnywhere, a remote control software
program for Windows. 

According to the Windows registry, the installed version of pcAnywhere
fails to prevent a local user from gaining SYSTEM privileges by
manipulating the 'Caller Properties' feature to run arbitrary commands
when pcAnywhere is configured to run as a service. 

See also :

http://securityresponse.symantec.com/avcenter/security/Content/2005.06.10.html

Solution : 

Upgrade to pcAnywhere version 11.5 or later. 

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:L/AC:L/Au:R/C:C/A:C/I:C/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
#  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Unless we're paranoid, make sure pcAnywhere is running as a service.
if (report_paranoia < 2) {
  services = get_kb_item("SMB/svcs");
  if (
    services &&
    (
      "awhost32" >!< services &&
      "pcAnywhere Host Service" >!< services
    )
  ) exit(0);
}


# Look in the registry for evidence of pcAnywhere.
key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{E05E8183-866A-11D3-97DF-0000F8D8F2E9}";
name = get_kb_item(string(key, "/DisplayName"));
if (name && "pcAnywhere" >< name) {
  ver = get_kb_item(string(key, "/DisplayVersion"));

  # There's a problem if it's before 11.5.
  if (ver && ver =~ "^([0-9]\.|10\.|11\.[0-4]\.)") {
    security_warning(0);
    exit(0);
  }
}
