#
# (C) Tenable Network Security
#


if (description) {
  script_id(20842);
  script_version("$Revision: 1.8 $");

  script_cve_id(
    "CVE-2005-4134",
    "CVE-2006-0292",
    "CVE-2006-0293",
    "CVE-2006-0294",
    "CVE-2006-0295",
    "CVE-2006-0296",
    "CVE-2006-0297",
    "CVE-2006-0298",
    "CVE-2006-0299"
  );
  script_bugtraq_id(15773, 16476, 16741);

  script_name(english:"Firefox < 1.5.0.1");
  script_summary(english:"Checks for Firefox < 1.5.0.1");

  desc = "
Synopsis :

A web browser on the remote host is prone to multiple flaws.

Description :

The remote Windows host is using Firefox, an alternative web browser. 

The installed version of Firefox contains various security issues, some
of which can be exploited to execute arbitrary code on the affected host
subject to the user's privileges. 

See also : 

http://www.mozilla.org/security/announce/2006/mfsa2006-01.html
http://www.mozilla.org/security/announce/2006/mfsa2006-02.html
http://www.mozilla.org/security/announce/2006/mfsa2006-03.html
http://www.mozilla.org/security/announce/2006/mfsa2006-04.html
http://www.mozilla.org/security/announce/2006/mfsa2006-05.html
http://www.mozilla.org/security/announce/2006/mfsa2006-06.html
http://www.mozilla.org/security/announce/2006/mfsa2006-07.html
http://www.mozilla.org/security/announce/2006/mfsa2006-08.html
http://www.securityfocus.com/archive/1/425590/30/0/threaded

Solution : 

Upgrade to Firefox 1.5.0.1 or later.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 
  script_dependencies("mozilla_org_installed.nasl");

  exit(0);
}


ver = get_kb_item("Mozilla/Firefox/Version");
if (!ver) exit(0);
ver = split(ver, sep:'.', keep:FALSE);
if (
  int(ver[0]) < 1 ||
  (
    int(ver[0]) == 1 &&
    (
      int(ver[1]) < 5 ||
      (int(ver[1]) == 5 && int(ver[2]) == 0 && int(ver[3]) < 1)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
