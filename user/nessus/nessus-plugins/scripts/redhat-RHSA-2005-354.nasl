#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17680);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0803", "CVE-2004-0804", "CVE-2004-0886", "CVE-2004-0888", "CVE-2004-1125");

 name["english"] = "RHSA-2005-354: tetex";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated tetex packages that fix several integer overflows are now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  TeTeX is an implementation of TeX for Linux or UNIX systems. TeX takes
  a text file and a set of formatting commands as input and creates a
  typesetter-independent .dvi (DeVice Independent) file as output.

  A number of security flaws have been found affecting libraries used
  internally within teTeX. An attacker who has the ability to trick a user
  into processing a malicious file with teTeX could cause teTeX to crash or
  possibly execute arbitrary code.

  A number of integer overflow bugs that affect Xpdf were discovered. The
  teTeX package contains a copy of the Xpdf code used for parsing PDF files
  and is therefore affected by these bugs. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the names CVE-2004-0888 and
  CVE-2004-1125 to these issues.

  A number of integer overflow bugs that affect libtiff were discovered. The
  teTeX package contains an internal copy of libtiff used for parsing TIFF
  image files and is therefore affected by these bugs. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
  names CVE-2004-0803, CVE-2004-0804 and CVE-2004-0886 to these issues.

  Also latex2html is added to package tetex-latex for 64bit platforms.

  Users of teTeX should upgrade to these updated packages, which contain
  backported patches and are not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-354.html
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
if ( rpm_check( reference:"tetex-1.0.7-38.5E.8", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-afm-1.0.7-38.5E.8", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-doc-1.0.7-38.5E.8", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-dvilj-1.0.7-38.5E.8", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-dvips-1.0.7-38.5E.8", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-fonts-1.0.7-38.5E.8", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-latex-1.0.7-38.5E.8", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-xdvi-1.0.7-38.5E.8", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-1.0.7-67.7", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-afm-1.0.7-67.7", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-dvips-1.0.7-67.7", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-fonts-1.0.7-67.7", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-latex-1.0.7-67.7", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tetex-xdvi-1.0.7-67.7", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"tetex-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0803", value:TRUE);
 set_kb_item(name:"CVE-2004-0804", value:TRUE);
 set_kb_item(name:"CVE-2004-0886", value:TRUE);
 set_kb_item(name:"CVE-2004-0888", value:TRUE);
 set_kb_item(name:"CVE-2004-1125", value:TRUE);
}
if ( rpm_exists(rpm:"tetex-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0803", value:TRUE);
 set_kb_item(name:"CVE-2004-0804", value:TRUE);
 set_kb_item(name:"CVE-2004-0886", value:TRUE);
 set_kb_item(name:"CVE-2004-0888", value:TRUE);
 set_kb_item(name:"CVE-2004-1125", value:TRUE);
}

set_kb_item(name:"RHSA-2005-354", value:TRUE);
