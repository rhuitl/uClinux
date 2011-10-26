#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17338);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1125", "CVE-2005-0064");

 name["english"] = "RHSA-2005-026: tetex";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated tetex packages that resolve security issues are now available for
  Red
  Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat
  Security Response Team.

  The tetex packages (teTeX) contain an implementation of TeX for Linux or
  UNIX systems.

  A buffer overflow flaw was found in the Gfx::doImage function of Xpdf which
  also affects teTeX due to a shared codebase. An attacker could construct a
  carefully crafted PDF file that could cause teTeX to crash or possibly
  execute arbitrary code when opened. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2004-1125 to
  this issue.

  A buffer overflow flaw was found in the Decrypt::makeFileKey2 function of
  Xpdf which also affects teTeX due to a shared codebase. An attacker could
  construct a carefully crafted PDF file that could cause teTeX to crash or
  possibly execute arbitrary code when opened. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2005-0064 to
  this issue.

  Users should update to these erratum packages which contain backported
  patches to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-026.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the tetex packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"tetex-2.0.2-22.EL4.4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-afm-2.0.2-22.EL4.4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-doc-2.0.2-22.EL4.4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-dvips-2.0.2-22.EL4.4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-fonts-2.0.2-22.EL4.4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-latex-2.0.2-22.EL4.4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-xdvi-2.0.2-22.EL4.4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"tetex-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2004-1125", value:TRUE);
 set_kb_item(name:"CVE-2005-0064", value:TRUE);
}

set_kb_item(name:"RHSA-2005-026", value:TRUE);
