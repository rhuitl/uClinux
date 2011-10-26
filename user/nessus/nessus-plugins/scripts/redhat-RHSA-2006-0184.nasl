#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20753);
 script_version ("$Revision: 1.2 $");
 script_bugtraq_id(16325);
 script_cve_id("CVE-2006-0019");

 name["english"] = "RHSA-2006-0184: kdelibs";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kdelibs packages are now available for Red Hat Enterprise Linux 4.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  kdelibs contains libraries for the K Desktop Environment (KDE).

  A heap overflow flaw was discovered affecting kjs, the JavaScript
  interpreter engine used by Konqueror and other parts of KDE. An attacker
  could create a malicious web site containing carefully crafted JavaScript
  code that would trigger this flaw and possibly lead to arbitrary code
  execution. The Common Vulnerabilities and Exposures project assigned the
  name CVE-2006-0019 to this issue.

  NOTE: this issue does not affect KDE in Red Hat Enterprise Linux 3 or 2.1.

  Users of KDE should upgrade to these updated packages, which contain a
  backported patch from the KDE security team correcting this issue as well
  as two bug fixes.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0184.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdelibs packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kdelibs-3.3.1-3.14", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-3.3.1-3.14", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kdelibs-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-0019", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0184", value:TRUE);
