#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21592);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2973", "CVE-2005-3272", "CVE-2005-3359", "CVE-2006-0555", "CVE-2006-0741", "CVE-2006-0744", "CVE-2006-1522", "CVE-2006-1525", "CVE-2006-1527", "CVE-2006-1528", "CVE-2006-1855", "CVE-2006-1856", "CVE-2006-1862", "CVE-2006-1864", "CVE-2006-2271", "CVE-2006-2272", "CVE-2006-2274");

 name["english"] = "RHSA-2006-0493:   kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages that fix several security issues in the Red Hat
  Enterprise Linux 4 kernel are now available.

  This security advisory has been rated as having important security impact
  by the Red Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  These new kernel packages contain fixes for various security issues.


  All Red Hat Enterprise Linux 4 users are advised to upgrade their kernels
  to the packages associated with their machine architectures and
  configurations as listed in this erratum.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0493.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the   kernel packages";
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
if ( rpm_check( reference:"  kernel-2.6.9-34.0.1.EL.i686.rpm                       34813080d97fdd6f647fd7d4f809c7fc", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-devel-2.6.9-34.0.1.EL.i686.rpm                 e78b9ccc0c954cff7cb40e6f02b24674", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-doc-2.6.9-34.0.1.EL.noarch.rpm                 4969d66062c65e2f969a5b23f3d038fb", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-hugemem-2.6.9-34.0.1.EL.i686.rpm               3c00e3363ab92e43224a3017fb7bb4a3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-hugemem-devel-2.6.9-34.0.1.EL.i686.rpm         861c261dc99531fecc8b90a579e3d406", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.6.9-34.0.1.EL.i686.rpm                   ac1a65bd4766603619c7871c8454312d", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-devel-2.6.9-34.0.1.EL.i686.rpm             20bb2e56287af558784e341a22ecc899", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"  kernel-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2973", value:TRUE);
 set_kb_item(name:"CVE-2005-3272", value:TRUE);
 set_kb_item(name:"CVE-2005-3359", value:TRUE);
 set_kb_item(name:"CVE-2006-0555", value:TRUE);
 set_kb_item(name:"CVE-2006-0741", value:TRUE);
 set_kb_item(name:"CVE-2006-0744", value:TRUE);
 set_kb_item(name:"CVE-2006-1522", value:TRUE);
 set_kb_item(name:"CVE-2006-1525", value:TRUE);
 set_kb_item(name:"CVE-2006-1527", value:TRUE);
 set_kb_item(name:"CVE-2006-1528", value:TRUE);
 set_kb_item(name:"CVE-2006-1855", value:TRUE);
 set_kb_item(name:"CVE-2006-1856", value:TRUE);
 set_kb_item(name:"CVE-2006-1862", value:TRUE);
 set_kb_item(name:"CVE-2006-1864", value:TRUE);
 set_kb_item(name:"CVE-2006-2271", value:TRUE);
 set_kb_item(name:"CVE-2006-2272", value:TRUE);
 set_kb_item(name:"CVE-2006-2274", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0493", value:TRUE);
