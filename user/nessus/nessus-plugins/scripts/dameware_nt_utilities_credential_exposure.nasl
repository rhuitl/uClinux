#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18117);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-1166");
  script_bugtraq_id(13200);

  name["english"] = "DameWare NT Utilities Authentication Credentials Persistence Weakness";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

Local user can obtain extra credentials.

Description :

According to its version number, the copy of DameWare NT Utilities
installed on the remote host allows a local user to recover
authentication credentials because the application stores sensitive
information in memory as plain text: username, password, remote user,
and remote hostname. 

See also :

http://www.shellsec.net/leer_advisory.php?id=7

Solution :

Upgrade to DameWare NT Utilities 4.9 or later.

Risk factor :

Low / CVSS Base Score : 2 
(AV:L/AC:H/Au:R/C:P/A:P/I:P/B:N)";

  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for authentication credentials persistence weakness in DameWare NT Utilities";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Look in the registry for the version of DameWare NT Utilities installed.
key1 = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{531C5E56-31E1-4797-AACB-2B17DE8A35D2}/DisplayName";
key2 = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{531C5E56-31E1-4797-AACB-2B17DE8A35D2}/DisplayVersion";
if (get_kb_item(key1)) {
  ver = get_kb_item(key2);
  # nb: the advisory claims versions 4.9 and below are vulnerable.
  if (ver && ver =~ "^([0-3]|4\.([0-8]|9\.0\.0$))") security_note(port);
}
