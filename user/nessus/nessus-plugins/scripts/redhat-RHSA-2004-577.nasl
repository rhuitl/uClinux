#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15629);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0803", "CVE-2004-0804", "CVE-2004-0886");

 name["english"] = "RHSA-2004-577: libtiff";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated libtiff packages that fix various buffer and integer overflows are
  now available.

  The libtiff package contains a library of functions for manipulating TIFF
  (Tagged Image File Format) image format files. TIFF is a widely used file
  format for bitmapped images.

  During a source code audit, Chris Evans discovered a number of integer
  overflow bugs that affect libtiff. An attacker who has the ability to trick
  a user into opening a malicious TIFF file could cause the application
  linked to libtiff to crash or possibly execute arbitrary code. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
  names CVE-2004-0886 and CVE-2004-0804 to these issues.

  Additionally, a number of buffer overflow bugs that affect libtiff have
  been found. An attacker who has the ability to trick a user into opening a
  malicious TIFF file could cause the application linked to libtiff to crash
  or possibly execute arbitrary code. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2004-0803 to
  this issue.

  All users are advised to upgrade to these errata packages, which contain
  fixes for these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-577.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libtiff packages";
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
if ( rpm_check( reference:"libtiff-3.5.5-17", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-devel-3.5.5-17", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-3.5.7-20.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-devel-3.5.7-20.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-3.5.7-20.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-3.5.7-20.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"libtiff-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0803", value:TRUE);
 set_kb_item(name:"CVE-2004-0804", value:TRUE);
 set_kb_item(name:"CVE-2004-0886", value:TRUE);
}
if ( rpm_exists(rpm:"libtiff-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0803", value:TRUE);
 set_kb_item(name:"CVE-2004-0804", value:TRUE);
 set_kb_item(name:"CVE-2004-0886", value:TRUE);
}

set_kb_item(name:"RHSA-2004-577", value:TRUE);
