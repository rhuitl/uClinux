#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22071);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-3404");

 name["english"] = "RHSA-2006-0598: gimp";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated gimp packages that fix a security issue are now available for Red
  Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The GIMP (GNU Image Manipulation Program) is an image composition and
  editing program.

  Henning Makholm discovered a buffer overflow bug in The GIMP XCF file
  loader. An attacker could create a carefully crafted image that could
  execute arbitrary code if opened by a victim. (CVE-2006-3404)

  Please note that this issue did not affect the gimp packages in Red Hat
  Enterprise Linux 2.1, or 3.

  Users of The GIMP should update to these erratum packages which contain a
  backported fix to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0598.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gimp packages";
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
if ( rpm_check( reference:"gimp-2.0.5-6", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gimp-devel-2.0.5-6", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gimp-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-3404", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0598", value:TRUE);
