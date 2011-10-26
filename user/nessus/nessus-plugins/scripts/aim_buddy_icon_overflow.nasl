#
# (C) Tenable Network Security
#


if (description) {
  script_id(18432);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-1891");
  script_bugtraq_id(13880);

  name["english"] = "AIM Buddy Icon Overflow Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote Windows host is susceptible to denial of service attacks. 

Description :

According to the Windows registry, the remote host has installed on it a
version of AOL Instant Messenger that has integer overflow in its GIF
parser, 'ateimg32.dll'.  Using a specially-crafted GIF file as a buddy
icon, an attacker can cause a crash of the affected host. 

See also : 

http://security-protocols.com/advisory/sp-x15-advisory.txt
http://archives.neohapsis.com/archives/bugtraq/2005-06/0032.html
http://archives.neohapsis.com/archives/bugtraq/2005-06/0039.html

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 3 
(AV:R/AC:H/Au:NR/C:N/A:C/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for buddy icon overflow vulnerability in AIM";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("aim_detect.nasl");
  script_require_keys("AIM/version");

  exit(0);
}


# Test an install.
ver = get_kb_item("AIM/version");
if (ver) {
  # There's a problem if the newest version is 5.9.3797 or below.
  iver = split(ver, sep:'.', keep:FALSE);
  if (
    int(iver[0]) < 5 ||
    (
      int(iver[0]) == 5 && 
      (
        int(iver[1]) < 9 ||
        (int(iver[1]) == 9 && int(iver[2]) <= 3797)
      )
    )
  ) security_note(port);
}
