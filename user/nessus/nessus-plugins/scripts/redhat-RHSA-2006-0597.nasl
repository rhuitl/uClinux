#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22070);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-3376");

 name["english"] = "RHSA-2006-0597: libwmf";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated libwmf packages that fix a security flaw are now available for Red
  Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Libwmf is a library for reading and converting Windows MetaFile vector
  graphics (WMF). Libwmf is used by packages such as The GIMP and
  ImageMagick.

  An integer overflow flaw was discovered in libwmf. An attacker could
  create a carefully crafted WMF flaw that could execute arbitrary code if
  opened by a victim. (CVE-2006-3376).

  Users of libwmf should update to these packages which contain a backported
  security patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0597.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libwmf packages";
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
if ( rpm_check( reference:"libwmf-0.2.8.3-5.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libwmf-devel-0.2.8.3-5.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"libwmf-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-3376", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0597", value:TRUE);
