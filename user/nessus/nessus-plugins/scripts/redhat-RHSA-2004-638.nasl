#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15995);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0941", "CVE-2004-0990");

 name["english"] = "RHSA-2004-638: gd";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated gd packages that fix security issues with overflow in various
  memory allocation calls are now available.

  The gd packages contain a graphics library used for the dynamic creation of
  images such as PNG and JPEG.

  Several buffer overflows were reported in various memory allocation calls.
  An attacker could create a carefully crafted image file in such a way that
  it could cause ImageMagick to execute arbitrary code when processing the
  image. The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2004-0990 to these issues.

  While researching the fixes to these overflows, additional buffer overflows
  were discovered in calls to gdMalloc. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2004-0941 to
  these issues.

  Users of gd should upgrade to these updated packages, which contain a
  backported security patch, and are not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-638.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gd packages";
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
if ( rpm_check( reference:"gd-1.8.4-4.21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gd-devel-1.8.4-4.21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gd-progs-1.8.4-4.21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gd-1.8.4-12.3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gd-devel-1.8.4-12.3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gd-progs-1.8.4-12.3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gd-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0941", value:TRUE);
 set_kb_item(name:"CVE-2004-0990", value:TRUE);
}
if ( rpm_exists(rpm:"gd-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0941", value:TRUE);
 set_kb_item(name:"CVE-2004-0990", value:TRUE);
}

set_kb_item(name:"RHSA-2004-638", value:TRUE);
