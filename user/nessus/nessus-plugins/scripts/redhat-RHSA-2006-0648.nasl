#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22293);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-3459", "CVE-2006-3460", "CVE-2006-3461", "CVE-2006-3462", "CVE-2006-3463", "CVE-2006-3464", "CVE-2006-3465");

 name["english"] = "RHSA-2006-0648: kdegraphics";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kdegraphics packages that fix several security flaws in kfax are
  now available for Red Hat Enterprise Linux 2.1, and 3.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The kdegraphics package contains graphics applications for the K Desktop
  Environment.

  Tavis Ormandy of Google discovered a number of flaws in libtiff during a
  security audit. The kfax application contains a copy of the libtiff code
  used for parsing TIFF files and is therefore affected by these flaws.
  An attacker who has the ability to trick a user into opening a malicious
  TIFF file could cause kfax to crash or possibly execute arbitrary code.
  (CVE-2006-3459, CVE-2006-3460, CVE-2006-3461, CVE-2006-3462, CVE-2006-3463,
  CVE-2006-3464, CVE-2006-3465)

  Red Hat Enterprise Linux 4 is not vulnerable to these issues as kfax uses
  the shared libtiff library which has been fixed in a previous update.

  Users of kfax should upgrade to these updated packages, which contain
  backported patches and are not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0648.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdegraphics packages";
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
if ( rpm_check( reference:"kdegraphics-2.2.2-4.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-devel-2.2.2-4.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-3.1.3-3.10", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-devel-3.1.3-3.10", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kdegraphics-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2006-3459", value:TRUE);
 set_kb_item(name:"CVE-2006-3460", value:TRUE);
 set_kb_item(name:"CVE-2006-3461", value:TRUE);
 set_kb_item(name:"CVE-2006-3462", value:TRUE);
 set_kb_item(name:"CVE-2006-3463", value:TRUE);
 set_kb_item(name:"CVE-2006-3464", value:TRUE);
 set_kb_item(name:"CVE-2006-3465", value:TRUE);
}
if ( rpm_exists(rpm:"kdegraphics-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-3459", value:TRUE);
 set_kb_item(name:"CVE-2006-3460", value:TRUE);
 set_kb_item(name:"CVE-2006-3461", value:TRUE);
 set_kb_item(name:"CVE-2006-3462", value:TRUE);
 set_kb_item(name:"CVE-2006-3463", value:TRUE);
 set_kb_item(name:"CVE-2006-3464", value:TRUE);
 set_kb_item(name:"CVE-2006-3465", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0648", value:TRUE);
