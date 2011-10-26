#
# (C) Tenable Network Security
#


if (description) {
  script_id(21205);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-1257");
  script_bugtraq_id(17134);
  script_xref(name:"OSVDB", value:"24121");

  script_name(english:"Commerce Server 2002 Authentication Bypass Vulnerability");
  script_summary(english:"Checks version of Commerce Server 2002");
 
  desc = "
Synopsis :

The remote web application may be vulnerable to an authentication
bypass vulnerability. 

Description :

The version of Microsoft Commerce Server 2002 installed on the remote
host may enable an attacker to bypass authentication if the sample
files from the 'AuthFiles' folder are installed under the web server's
document root. 

Note that successful exploitation of this issue requires knowledge of
the location of the sample files as well as a valid user name. 

See also :

http://www.securityfocus.com/archive/1/archive/1/427974/100/0/threaded
http://www.nessus.org/u?8f31fa25

Solution :

Apply Commerce Server 2002 Service Pack 2 or later. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1);


# Get Commerce Server's version number from the registry.
subkey = "{E39DA45E-B9E6-412D-BEDE-EFD7BC1DACA6}";
key = string("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/", subkey, "/DisplayVersion");
ver = get_kb_item(key);
if (isnull(ver)) exit(0);


# There's a problem if the version is < 4.5.3320.00.
iver = split(ver, sep:'.', keep:FALSE);
if (
  int(iver[0]) < 4 ||
  (
    int(iver[0]) == 4 &&
    (
      int(iver[1]) < 5 ||
      (int(iver[1]) == 5 && int(iver[2]) < 3320)
    )
  )
) security_warning(get_kb_item("SMB/transport"));
