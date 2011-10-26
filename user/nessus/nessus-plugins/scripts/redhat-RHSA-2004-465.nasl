#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14735);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0817");

 name["english"] = "RHSA-2004-465: imlib";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated imlib package that fixes several heap overflows is now
  available.

  Imlib is an image loading and rendering library.

  Several heap overflow flaws were found in the imlib BMP image handler. An
  attacker could create a carefully crafted BMP file in such a way that it
  could cause an application linked with imlib to execute arbitrary code when
  the file was opened by a victim. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CVE-2004-0817 to this issue.

  Users of imlib should update to this updated package which contains
  backported patches and is not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-465.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the imlib packages";
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
if ( rpm_check( reference:"imlib-1.9.13-4.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-cfgeditor-1.9.13-4.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-devel-1.9.13-4.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-1.9.13-13.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-devel-1.9.13-13.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"imlib-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0817", value:TRUE);
}
if ( rpm_exists(rpm:"imlib-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0817", value:TRUE);
}

set_kb_item(name:"RHSA-2004-465", value:TRUE);
