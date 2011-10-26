#
# (C) Tenable Network Security
#


if (description) {
  script_id(20395);
  script_version("$Revision: 1.7 $");

  script_cve_id(
    "CVE-2005-2340",
    "CVE-2005-3707",
    "CVE-2005-3708",
    "CVE-2005-3709",
    "CVE-2005-3710",
    "CVE-2005-3711",
    "CVE-2005-3713",
    "CVE-2005-4092"
  );
  script_bugtraq_id(16202);

  script_name(english:"Quicktime < 7.0.4 (Windows)");
  script_summary(english:"Checks for Quicktime < 7.0.4 on Windows");
 
  desc = "
Synopsis :

The remote version of QuickTime is affected by multiple code execution
vulnerabilities. 

Description :

The remote Windows host is running a version of Quicktime prior to
7.0.4. 

The remote version of Quicktime is vulnerable to various buffer
overflows involving specially-crafted image and media files.  An
attacker may be able to leverage these issues to execute arbitrary
code on the remote host by sending a malformed file to a victim and
have him open it using QuickTime player. 

See also : 

http://lists.grok.org.uk/pipermail/full-disclosure/2006-January/041289.html
http://lists.grok.org.uk/pipermail/full-disclosure/2006-January/041290.html
http://lists.grok.org.uk/pipermail/full-disclosure/2006-January/041291.html
http://lists.grok.org.uk/pipermail/full-disclosure/2006-January/041292.html
http://lists.grok.org.uk/pipermail/full-disclosure/2006-January/041333.html
http://lists.grok.org.uk/pipermail/full-disclosure/2006-January/041334.html
http://lists.grok.org.uk/pipermail/full-disclosure/2006-January/041335.html
http://www.cirt.dk/advisories/cirt-41-advisory.pdf
http://lists.apple.com/archives/security-announce/2006/Jan/msg00001.html
http://docs.info.apple.com/article.html?artnum=303101

Solution :

Upgrade to Quicktime version 7.0.4 or later.

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("quicktime_installed.nasl");
  script_require_keys("SMB/QuickTime/Version");

  exit(0);
}


ver = get_kb_item("SMB/QuickTime/Version");
if (ver && ver =~ "^([0-6]\.|7\.0\.[0-3]$)") security_warning(get_kb_item("SMB/transport"));
