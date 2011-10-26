#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12402);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0015");
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0434");

 name["english"] = "RHSA-2003-197: xpdf";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Xpdf packages are available that fix a vulnerability where a
  malicious PDF document could run arbitrary code.

  [Updated 21 July 2003]
  Updated packages are now available, as the original errata packages did not
  fix all possible ways of exploiting this vulnerability.

  Xpdf is an X Window System based viewer for Portable Document Format
  (PDF) files.

  Martyn Gilmore discovered a flaw in various PDF viewers and readers. An
  attacker can embed malicious external-type hyperlinks that if activated or
  followed by a victim can execute arbitrary shell commands. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2003-0434 to this issue.

  All users of Xpdf are advised to upgrade to these errata packages, which
  contain a patch correcting this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2003-197.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xpdf packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"xpdf-0.92-10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"xpdf-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0434", value:TRUE);
}

set_kb_item(name:"RHSA-2003-197", value:TRUE);
