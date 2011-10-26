#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18444);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0136", "CVE-2005-1264");

 name["english"] = "RHSA-2005-420:   kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages are now available as part of ongoing support
  and maintenance of Red Hat Enterprise Linux version 4. This is the
  first regular update.

  The Linux kernel handles the basic functions of the operating system.

  This is the first regular kernel update to Red Hat Enterprise Linux 4.

  A flaw affecting the auditing code was discovered. On Itanium
  architectures a local user could use this flaw to cause a denial of service
  (crash). This issue is rated as having important security impact
  (CVE-2005-0136).

  A flaw was discovered in the servicing of a raw device ioctl. A local user
  who has access to raw devices could use this flaw to write to kernel memory
  and cause a denial of service or potentially gain privileges. This issue
  is rated as having moderate security impact (CVE-2005-1264).

  New features introduced by this update include:
  - Fixed TCP BIC congestion handling.
  - Diskdump support for more controllers (megaraid, SATA)
  - Device mapper multipath support
  - AMD64 dual core support.
  - Intel ICH7 hardware support.

  There were many bug fixes in various parts of the kernel. The ongoing
  effort to resolve these problems has resulted in a marked improvement
  in the reliability and scalability of Red Hat Enterprise Linux 4.

  The following device drivers have been upgraded to new versions:
  ata_piix -------- 1.03
  bonding --------- 2.6.1
  e1000 ----------- 5.6.10.1-k2-NAPI
  e100 ------------ 3.3.6-k2-NAPI
  ibmveth --------- 1.03
  libata ---------- 1.02 to 1.10
  lpfc ------------ 0:8.0.16 to 0:8.0.16.6_x2
  megaraid_mbox --- 2.20.4.0 to 2.20.4.5
  megaraid_mm ----- 2.20.2.0-rh1 to 2.20.2.5
  sata_nv --------- 0.03 to 0.6
  sata_promise ---- 1.00 to 1.01
  sata_sil -------- 0.8
  sata_sis -------- 0.5
  sata_svw -------- 1.05
  sata_sx4 -------- 0.7
  sata_via -------- 1.0
  sata_vsc -------- 1.0
  tg3 ------------- 3.22-rh
  ipw2100 --------- 1.0.3
  ipw2200 --------- 1.0.0

  All Red Hat Enterprise Linux 4 users are advised to upgrade their
  kernels to the packages associated with their machine architectures
  and configurations as listed in this erratum.




Solution : http://rhn.redhat.com/errata/RHSA-2005-420.html
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
if ( rpm_check( reference:"kernel-2.6.9-11.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-11.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-11.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-11.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-11.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-11.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-11.EL", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"  kernel-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0136", value:TRUE);
 set_kb_item(name:"CVE-2005-1264", value:TRUE);
}

set_kb_item(name:"RHSA-2005-420", value:TRUE);
