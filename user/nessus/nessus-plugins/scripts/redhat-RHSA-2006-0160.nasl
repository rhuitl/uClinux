#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20752);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3191", "CVE-2005-3192", "CVE-2005-3193", "CVE-2005-3624", "CVE-2005-3625", "CVE-2005-3626", "CVE-2005-3627", "CVE-2005-3628");

 name["english"] = "RHSA-2006-0160: tetex";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated tetex packages that fix several integer overflows are now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  TeTeX is an implementation of TeX. TeX takes a text file and a set of
  formatting commands as input and creates a typesetter-independent .dvi
  (DeVice Independent) file as output.

  Several flaws were discovered in the teTeX PDF parsing library. An attacker
  could construct a carefully crafted PDF file that could cause teTeX to
  crash or possibly execute arbitrary code when opened. The Common
  Vulnerabilities and Exposures project assigned the names CVE-2005-3191,
  CVE-2005-3192, CVE-2005-3193, CVE-2005-3624, CVE-2005-3625, CVE-2005-3626,
  CVE-2005-3627 and CVE-2005-3628 to these issues.

  Users of teTeX should upgrade to these updated packages, which contain
  backported patches and are not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0160.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the tetex packages";
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
if ( rpm_check( reference:"tetex-1.0.7-38.5E.10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-afm-1.0.7-38.5E.10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-doc-1.0.7-38.5E.10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-dvilj-1.0.7-38.5E.10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-dvips-1.0.7-38.5E.10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-fonts-1.0.7-38.5E.10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-latex-1.0.7-38.5E.10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-xdvi-1.0.7-38.5E.10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-1.0.7-67.9", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-afm-1.0.7-67.9", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-dvips-1.0.7-67.9", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-fonts-1.0.7-67.9", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-latex-1.0.7-67.9", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-xdvi-1.0.7-67.9", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-2.0.2-22.EL4.7", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-afm-2.0.2-22.EL4.7", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-doc-2.0.2-22.EL4.7", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-dvips-2.0.2-22.EL4.7", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-fonts-2.0.2-22.EL4.7", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-latex-2.0.2-22.EL4.7", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-xdvi-2.0.2-22.EL4.7", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"tetex-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-3191", value:TRUE);
 set_kb_item(name:"CVE-2005-3192", value:TRUE);
 set_kb_item(name:"CVE-2005-3193", value:TRUE);
 set_kb_item(name:"CVE-2005-3624", value:TRUE);
 set_kb_item(name:"CVE-2005-3625", value:TRUE);
 set_kb_item(name:"CVE-2005-3626", value:TRUE);
 set_kb_item(name:"CVE-2005-3627", value:TRUE);
 set_kb_item(name:"CVE-2005-3628", value:TRUE);
}
if ( rpm_exists(rpm:"tetex-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-3191", value:TRUE);
 set_kb_item(name:"CVE-2005-3192", value:TRUE);
 set_kb_item(name:"CVE-2005-3193", value:TRUE);
 set_kb_item(name:"CVE-2005-3624", value:TRUE);
 set_kb_item(name:"CVE-2005-3625", value:TRUE);
 set_kb_item(name:"CVE-2005-3626", value:TRUE);
 set_kb_item(name:"CVE-2005-3627", value:TRUE);
 set_kb_item(name:"CVE-2005-3628", value:TRUE);
}
if ( rpm_exists(rpm:"tetex-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-3191", value:TRUE);
 set_kb_item(name:"CVE-2005-3192", value:TRUE);
 set_kb_item(name:"CVE-2005-3193", value:TRUE);
 set_kb_item(name:"CVE-2005-3624", value:TRUE);
 set_kb_item(name:"CVE-2005-3625", value:TRUE);
 set_kb_item(name:"CVE-2005-3626", value:TRUE);
 set_kb_item(name:"CVE-2005-3627", value:TRUE);
 set_kb_item(name:"CVE-2005-3628", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0160", value:TRUE);
