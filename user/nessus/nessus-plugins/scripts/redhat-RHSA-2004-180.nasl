#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12492);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0421");

 name["english"] = "RHSA-2004-180: libpng";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated libpng packages that fix a out of bounds memory access are now
  available.

  The libpng package contains a library of functions for creating and
  manipulating PNG (Portable Network Graphics) image format files.

  Steve Grubb discovered a out of bounds memory access flaw in libpng. An
  attacker could carefully craft a PNG file in such a way that it would cause
  an application linked to libpng to crash when opened by a victim. This
  issue may not be used to execute arbitrary code.

  Users are advised to upgrade to these updated packages that contain a
  backported security fix not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-180.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libpng packages";
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
if ( rpm_check( reference:"libpng-1.0.14-0.7x.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng-devel-1.0.14-0.7x.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng-1.2.2-21", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng-devel-1.2.2-21", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng10-1.0.13-12", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng10-devel-1.0.13-12", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng-1.2.2-21", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"libpng-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0421", value:TRUE);
}
if ( rpm_exists(rpm:"libpng-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0421", value:TRUE);
}

set_kb_item(name:"RHSA-2004-180", value:TRUE);
