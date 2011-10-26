#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14213);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2004-0597", "CVE-2004-0598", "CVE-2004-0599", "CVE-2002-1363");

 name["english"] = "RHSA-2004-402: libpng";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated libpng packages that fix several issues are now available.

  The libpng package contains a library of functions for creating and
  manipulating PNG (Portable Network Graphics) image format files.

  During a source code audit, Chris Evans discovered several buffer overflows
  in libpng. An attacker could create a carefully crafted PNG file in such a
  way that it would cause an application linked with libpng to execute
  arbitrary code when the file was opened by a victim. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-0597 to these issues.

  In addition, this audit discovered a potential NULL pointer dereference in
  libpng (CVE-2004-0598) and several integer overflow issues (CVE-2004-0599).
  An attacker could create a carefully crafted PNG file in such a way that
  it would cause an application linked with libpng to crash when the file was
  opened by the victim.

  Red Hat would like to thank Chris Evans for discovering these issues.

  For users of Red Hat Enterprise Linux 2.1 these patches also include a more
  complete fix for the out of bounds memory access flaw (CVE-2002-1363).

  All users are advised to update to the updated libpng packages which
  contain backported security patches and are not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-402.html
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
if ( rpm_check( reference:"libpng-1.0.14-7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng-devel-1.0.14-7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng-1.2.2-25", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng-devel-1.2.2-25", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng10-1.0.13-15", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng10-devel-1.0.13-15", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng-1.2.2-25", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng-1.2.2-25", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"libpng-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0597", value:TRUE);
 set_kb_item(name:"CVE-2004-0598", value:TRUE);
 set_kb_item(name:"CVE-2004-0599", value:TRUE);
 set_kb_item(name:"CVE-2002-1363", value:TRUE);
}
if ( rpm_exists(rpm:"libpng-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0597", value:TRUE);
 set_kb_item(name:"CVE-2004-0598", value:TRUE);
 set_kb_item(name:"CVE-2004-0599", value:TRUE);
 set_kb_item(name:"CVE-2002-1363", value:TRUE);
}

set_kb_item(name:"RHSA-2004-402", value:TRUE);
