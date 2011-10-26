#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21033);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0095");

 name["english"] = "RHSA-2006-0132:   kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kernel packages are now available as part of ongoing support
  and maintenance of Red Hat Enterprise Linux version 4. This is the
  third regular update.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  This is the third regular kernel update to Red Hat Enterprise Linux 4.

  New features introduced in this update include:

  - Open InfiniBand (OpenIB) support

  - Serial Attached SCSI support

  - NFS access control lists, asynchronous I/O

  - IA64 multi-core support and sgi updates

  - Large SMP CPU limits increased using the largesmp kernel: Up to 512 CPUs
  in ia64, 128 in ppc64, and 64 in AMD64 and Intel EM64T

  - Improved read-ahead performance

  - Common Internet File System (CIFS) update

  - Error Detection and Correction (EDAC) modules

  - Unisys support

  There were several bug fixes in various parts of the kernel. The ongoing
  effort to resolve these problems has resulted in a marked improvement
  in the reliability and scalability of Red Hat Enterprise Linux 4.

  The following security bug was fixed in this update:

  - dm-crypt did not clear a structure before freeing it, which could allow
  local users to discover information about cryptographic keys (CVE-2006-0095)

  The following device drivers have been upgraded to new versions:

  cciss: 2.6.8 to 2.6.8-rh1
  ipmi_devintf: 33.4 to 33.11
  ipmi_msghandler: 33.4 to 33.11
  ipmi_poweroff: 33.4 to 33.11
  ipmi_si: 33.4 to 33.11
  ipmi_watchdog: 33.4 to 33.11
  mptbase: 3.02.18 to 3.02.60.01rh
  e1000: 6.0.54-k2-NAPI to 6.1.16-k2-NAPI
  ixgb: 1.0.95-k2-NAPI to 1.0.100-k2-NAPI
  tg3: 3.27-rh to 3.43-rh
  aacraid: 1.1.2-lk2 to 1.1-5[2412]
  ahci: 1.01 to 1.2
  ata_piix: 1.03 to 1.05
  iscsi_sfnet: 4:0.1.11-1 to 4:0.1.11-2
  libata: 1.11 to 1.20
  qla2100: 8.01.00b5-rh2 to 8.01.02-d3
  qla2200: 8.01.00b5-rh2 to 8.01.02-d3
  qla2300: 8.01.00b5-rh2 to 8.01.02-d3
  qla2322: 8.01.00b5-rh2 to 8.01.02-d3
  qla2xxx: 8.01.00b5-rh2 to 8.01.02-d3
  qla6312: 8.01.00b5-rh2 to 8.01.02-d3
  sata_nv: 0.6 to 0.8
  sata_promise: 1.01 to 1.03
  sata_svw: 1.06 to 1.07
  sata_sx4: 0.7 to 0.8
  sata_vsc: 1.0 to 1.1
  cifs: 1.20 to 1.34

  Added drivers:

  bnx2: 1.4.25
  dell_rbu: 0.7
  hangcheck-timer: 0.9.0
  ib_mthca: 0.06
  megaraid_sas: 00.00.02.00
  qla2400: 8.01.02-d3
  typhoon: 1.5.7

  All Red Hat Enterprise Linux 4 users are advised to upgrade their
  kernels to the packages associated with their machine architectures
  and configurations as listed in this erratum.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0132.html
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
if ( rpm_check( reference:"  kernel-2.6.9-34.EL.i686.rpm                       2064a3c58b05e968679207687dbc4298", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-devel-2.6.9-34.EL.i686.rpm                 46608bf806692c1646d89c6c1355dbf5", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-doc-2.6.9-34.EL.noarch.rpm                 cd967a8e145158552f88654d643cf6de", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-hugemem-2.6.9-34.EL.i686.rpm               a397a5ec8ef28298565091bb8c671c05", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-hugemem-devel-2.6.9-34.EL.i686.rpm         5df428f24b225b21ae93fad89a2e5eb1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.6.9-34.EL.i686.rpm                   6e01fc2120b5124c16d8adc7b970739a", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-devel-2.6.9-34.EL.i686.rpm             0880e12ccbbbcbff6959dbbc447dbb3b", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"  kernel-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-0095", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0132", value:TRUE);
