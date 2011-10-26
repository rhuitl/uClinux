#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17183);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1056", "CVE-2004-1137", "CVE-2004-1235", "CVE-2005-0001", "CVE-2005-0090", "CVE-2005-0091", "CVE-2005-0092", "CVE-2005-0176", "CVE-2005-0177", "CVE-2005-0178", "CVE-2005-0179", "CVE-2005-0180", "CVE-2005-0204");

 name["english"] = "RHSA-2005-092:   kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages that fix several security issues are now available
  for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.


  All Red Hat Enterprise Linux 4 users are advised to upgrade their
  kernels to the packages associated with their machine architectures
  and configurations as listed in this erratum.


Solution : http://rhn.redhat.com/errata/RHSA-2005-092.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the   kernel packages";
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
if ( rpm_check( reference:"kernel-2.6.9-5.0.3.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-5.0.3.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-5.0.3.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-5.0.3.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-5.0.3.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-5.0.3.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-5.0.3.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kernel-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2004-1056", value:TRUE);
 set_kb_item(name:"CVE-2004-1137", value:TRUE);
 set_kb_item(name:"CVE-2004-1235", value:TRUE);
 set_kb_item(name:"CVE-2005-0001", value:TRUE);
 set_kb_item(name:"CVE-2005-0090", value:TRUE);
 set_kb_item(name:"CVE-2005-0091", value:TRUE);
 set_kb_item(name:"CVE-2005-0092", value:TRUE);
 set_kb_item(name:"CVE-2005-0176", value:TRUE);
 set_kb_item(name:"CVE-2005-0177", value:TRUE);
 set_kb_item(name:"CVE-2005-0178", value:TRUE);
 set_kb_item(name:"CVE-2005-0179", value:TRUE);
 set_kb_item(name:"CVE-2005-0180", value:TRUE);
 set_kb_item(name:"CVE-2005-0204", value:TRUE);
}

set_kb_item(name:"RHSA-2005-092", value:TRUE);
