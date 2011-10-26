#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22121);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-2776", "CVE-2006-2778", "CVE-2006-2779", "CVE-2006-2780", "CVE-2006-2782", "CVE-2006-2783", "CVE-2006-2784", "CVE-2006-2785", "CVE-2006-2786", "CVE-2006-2787", "CVE-2006-2788", "CVE-2006-3113", "CVE-2006-3677", "CVE-2006-3801", "CVE-2006-3802", "CVE-2006-3803", "CVE-2006-3805", "CVE-2006-3806", "CVE-2006-3807", "CVE-2006-3808", "CVE-2006-3809", "CVE-2006-3810", "CVE-2006-3811", "CVE-2006-3812");

 name["english"] = "RHSA-2006-0610: firefox";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated firefox packages that fix several security bugs are now available
  for Red Hat Enterprise Linux 4.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla Firefox is an open source Web browser.

  The Mozilla Foundation has discontinued support for the Mozilla Firefox
  1.0 branch. This update deprecates the Mozilla Firefox 1.0 branch in
  Red Hat Enterprise Linux 4 in favor of the supported Mozilla Firefox
  1.5 branch.

  This update also resolves a number of outstanding Firefox security issues.

  Users of Firefox are advised to upgrade to this update, which contains
  Firefox version 1.5.0.5 that corrects these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0610.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the firefox packages";
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
if ( rpm_check( reference:"firefox-1.5.0.5-0.el4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"firefox-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-2776", value:TRUE);
 set_kb_item(name:"CVE-2006-2778", value:TRUE);
 set_kb_item(name:"CVE-2006-2779", value:TRUE);
 set_kb_item(name:"CVE-2006-2780", value:TRUE);
 set_kb_item(name:"CVE-2006-2782", value:TRUE);
 set_kb_item(name:"CVE-2006-2783", value:TRUE);
 set_kb_item(name:"CVE-2006-2784", value:TRUE);
 set_kb_item(name:"CVE-2006-2785", value:TRUE);
 set_kb_item(name:"CVE-2006-2786", value:TRUE);
 set_kb_item(name:"CVE-2006-2787", value:TRUE);
 set_kb_item(name:"CVE-2006-2788", value:TRUE);
 set_kb_item(name:"CVE-2006-3113", value:TRUE);
 set_kb_item(name:"CVE-2006-3677", value:TRUE);
 set_kb_item(name:"CVE-2006-3801", value:TRUE);
 set_kb_item(name:"CVE-2006-3802", value:TRUE);
 set_kb_item(name:"CVE-2006-3803", value:TRUE);
 set_kb_item(name:"CVE-2006-3805", value:TRUE);
 set_kb_item(name:"CVE-2006-3806", value:TRUE);
 set_kb_item(name:"CVE-2006-3807", value:TRUE);
 set_kb_item(name:"CVE-2006-3808", value:TRUE);
 set_kb_item(name:"CVE-2006-3809", value:TRUE);
 set_kb_item(name:"CVE-2006-3810", value:TRUE);
 set_kb_item(name:"CVE-2006-3811", value:TRUE);
 set_kb_item(name:"CVE-2006-3812", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0610", value:TRUE);
