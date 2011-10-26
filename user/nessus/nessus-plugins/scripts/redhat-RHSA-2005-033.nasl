#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17167);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0087");

 name["english"] = "RHSA-2005-033: alsa";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated alsa-lib package that fixes a flaw that disabled stack execution
  protection is now available for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red Hat
  Security Response Team.

  The alsa-lib package provides a library of functions for communication with
  kernel sound drivers.

  A flaw in the alsa mixer code was discovered that caused stack
  execution protection to be disabled for the libasound.so library.
  The effect of this flaw is that stack execution protection, through NX or
  Exec-Shield, would be disabled for any application linked to libasound.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2005-0087 to this issue

  Users are advised to upgrade to this updated package, which contains a
  patched version of the library which correctly enables stack execution
  protection.




Solution : http://rhn.redhat.com/errata/RHSA-2005-033.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the alsa packages";
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
if ( rpm_check( reference:"alsa-lib-1.0.6-5.RHEL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"alsa-lib-devel-1.0.6-5.RHEL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"alsa-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0087", value:TRUE);
}

set_kb_item(name:"RHSA-2005-033", value:TRUE);
