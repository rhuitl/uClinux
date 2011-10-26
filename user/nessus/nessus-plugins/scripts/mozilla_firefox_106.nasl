#
# (C) Tenable Network Security
#


if (description) {
  script_id(19719);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2005-2602", "CVE-2005-2871", "CVE-2005-3089");
  script_bugtraq_id(14526, 14784, 14916, 14917, 14918, 14919, 14920, 14921, 14923, 14924);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"19255");
    script_xref(name:"OSVDB", value:"19615");
  }

  name["english"] = "Firefox < 1.0.7";
  script_name(english:name["english"]);

  desc["english"] = "
Synopsis :

A web browser on the remote host is prone to multiple flaws, including
arbitrary code execution.

Description :

The remote host is using Firefox, an alternative web browser.

The installed version of Firefox contains various security issues,
several of which are critical as they can be easily exploited to
execute arbitrary shell code on the remote host. 

See also : 

http://www.securityfocus.com/archive/1/407704
http://security-protocols.com/advisory/sp-x17-advisory.txt
http://www.mozilla.org/security/idn.html
http://www.mozilla.org/security/announce/2005/mfsa2005-58.html

Solution : 

Upgrade to Firefox 1.0.7 or later.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Determines the version of Firefox";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");
 
  script_dependencies("mozilla_org_installed.nasl");

  exit(0);
}


ver = get_kb_item("Mozilla/Firefox/Version");
if (
  ver &&
  ver =~ "^(0\.|1\.0\.[0-6]([^0-9]|$))"
) {
  security_hole(0);
  exit(0);
}
