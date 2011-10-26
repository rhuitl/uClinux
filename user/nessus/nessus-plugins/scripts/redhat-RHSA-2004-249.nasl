#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12507);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-1363");

 name["english"] = "RHSA-2004-249: libpng";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated libpng packages that fix a possible buffer overflow are now
  available.

  The libpng package contains a library of functions for creating and
  manipulating PNG (Portable Network Graphics) image format files.

  During an audit of Red Hat Linux updates, the Fedora Legacy team found a
  security issue in libpng that had not been fixed in Red Hat Enterprise
  Linux 3. An attacker could carefully craft a PNG file in such a way that
  it would cause an application linked to libpng to crash or potentially
  execute arbitrary code when opened by a victim.

  Note: this issue does not affect Red Hat Enterprise Linux 2.1

  Users are advised to upgrade to these updated packages that contain a
  backported security fix and are not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-249.html
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
if ( rpm_check( reference:"libpng-1.2.2-24", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng-devel-1.2.2-24", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng10-1.0.13-14", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng10-devel-1.0.13-14", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng-1.2.2-24", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"libpng-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2002-1363", value:TRUE);
}

set_kb_item(name:"RHSA-2004-249", value:TRUE);
