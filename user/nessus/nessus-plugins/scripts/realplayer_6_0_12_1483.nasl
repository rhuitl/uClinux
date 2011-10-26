#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21140);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-2922", "CVE-2005-2936", "CVE-2006-0323", "CVE-2006-1370");
  script_bugtraq_id(15448, 17202);

  script_name(english:"RealPlayer for Windows < 6.0.12.1483");
  script_summary(english:"Checks version of RealPlayer for Windows");
 
  desc = "
Synopsis :

The remote Windows application is affected by several issues. 

Description :

According to its version number, the installed version of RealPlayer /
RealOne Player / RealPlayer Enterprise on the remote Windows host
suffers from one or more buffer overflows involving maliciously-
crafted SWF and MBC files as well as web pages.  In addition, it also
may be affected by a local privilege escalation issue. 

See also :

http://www.idefense.com/intelligence/vulnerabilities/display.php?id=340
http://www.idefense.com/intelligence/vulnerabilities/display.php?id=404
http://service.real.com/realplayer/security/03162006_player/en/

Solution :

Upgrade according to the vendor advisory referenced above. 

Risk factor : 

High / CVSS Base Score : 7.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:C/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("realplayer_detect.nasl");
  script_require_keys("SMB/RealPlayer/Version");

  exit(0);
}


# Check version of RealPlayer.
ver = get_kb_item("SMB/RealPlayer/Version");
if (!ver) exit(0);

# There's a problem if the version is before 6.0.12.1483.
iver = split(ver, sep:'.', keep:FALSE);
if (
  int(iver[0]) < 6 ||
  (
    int(iver[0]) == 6 &&
    int(iver[1]) == 0 && 
    (
      int(iver[2]) < 12 ||
      (int(iver[2]) == 12 && int(iver[3]) < 1483)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
