#
# (C) Tenable Network Security
#


if (description) {
  script_id(20184);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-2629", "CVE-2005-2630", "CVE-2005-3677");
  script_bugtraq_id(15381, 15382, 15383, 15398);
  script_xref(name:"OSVDB", value:"18827");

  script_name(english:"RealPlayer for Windows Multiple Vulnerabilities (2)");
  script_summary(english:"Checks for multiple vulnerabilities in RealPlayer for Windows (2)");
 
  desc = "
Synopsis :

The remote Windows application is affected by several overflow
vulnerabilities. 

Description :

According to its version number, the installed version of RealPlayer /
RealOne Player / RealPlayer Enterprise for Windows on the remote host
is prone to buffer overflow and heap overflow vulnerabilities.  An
attacker may be able to leverage these issues to execute arbitrary
code on the remote host subject to the permissions of the user running
the affected application.  Note that a user doesn't necessarily need
to explicitly access a malicious media file since the browser may
automatically pass to the application RealPlayer skin files (ie, files
with the extension '.rjs'). 

See also : 

http://research.eeye.com/html/advisories/published/AD20051110a.html
http://research.eeye.com/html/advisories/published/AD20051110b.html
http://www.securityfocus.com/archive/1/416475
http://service.real.com/help/faq/security/security111005.html
http://service.real.com/help/faq/security/051110_player/EN/

Solution :

Upgrade according to the vendor advisories referenced above.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("realplayer_detect.nasl");
  script_require_keys("SMB/RealPlayer/Version");

  exit(0);
}


# Check version of RealPlayer.
ver = get_kb_item("SMB/RealPlayer/Version");
if (ver) {
  # There's a problem if the version is 6.0.12.1235 or older.
  iver = split(ver, sep:'.', keep:FALSE);
  if (
    int(iver[0]) < 6 ||
    (
      int(iver[0]) == 6 &&
      int(iver[1]) == 0 && 
      (
        int(iver[2]) < 12 ||
        (int(iver[2]) == 12 && int(iver[3]) <= 1235)
      )
    )
  ) security_hole(get_kb_item("SMB/transport"));
}
