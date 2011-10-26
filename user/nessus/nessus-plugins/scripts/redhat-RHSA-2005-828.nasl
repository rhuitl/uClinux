#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20145);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2974", "CVE-2005-3350");

 name["english"] = "RHSA-2005-828: libungif";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated libungif packages that fix two security issues are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The libungif package contains a shared library of functions for loading and
  saving GIF format image files.

  Several bugs in the way libungif decodes GIF images were discovered. An
  attacker could create a carefully crafted GIF image file in such a way that
  it could cause an application linked with libungif to crash or execute
  arbitrary code when the file is opened by a victim. The Common
  Vulnerabilities and Exposures project has assigned the names CVE-2005-2974
  and CVE-2005-3350 to these issues.

  All users of libungif are advised to upgrade to these updated packages,
  which contain backported patches that resolve these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-828.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libungif packages";
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
if ( rpm_check( reference:"libungif-4.1.0-9.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libungif-devel-4.1.0-9.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libungif-progs-4.1.0-9.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libungif-4.1.0-15.el3.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libungif-devel-4.1.0-15.el3.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libungif-4.1.3-1.el4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libungif-devel-4.1.3-1.el4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libungif-progs-4.1.3-1.el4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"libungif-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-2974", value:TRUE);
 set_kb_item(name:"CVE-2005-3350", value:TRUE);
}
if ( rpm_exists(rpm:"libungif-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-2974", value:TRUE);
 set_kb_item(name:"CVE-2005-3350", value:TRUE);
}
if ( rpm_exists(rpm:"libungif-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2974", value:TRUE);
 set_kb_item(name:"CVE-2005-3350", value:TRUE);
}

set_kb_item(name:"RHSA-2005-828", value:TRUE);
