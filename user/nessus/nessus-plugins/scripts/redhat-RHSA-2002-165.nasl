#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12317);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-0835");

 name["english"] = "RHSA-2002-165: pxe";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated PXE packages are now available for Red Hat Linux Advanced Server
  which fix a vulnerability that can crash the PXE server using certain
  DHCP packets.

  The PXE package contains the PXE (Preboot eXecution Environment)
  server and code needed for Linux to boot from a boot disk image on a
  Linux PXE server.

  It was found that the PXE server could be crashed using DHCP packets from
  some Voice Over IP (VOIP) phones. This bug could be used to cause a denial
  of service (DoS) attack on remote systems by using malicious packets.

  Users of PXE on Red Hat Linux Advanced Server are advised to upgrade to the
  new release which contains a version of PXE that is not vulnerable to this
  issue.




Solution : http://rhn.redhat.com/errata/RHSA-2002-165.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the pxe packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"pxe-0.1-31.99.7.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"pxe-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-0835", value:TRUE);
}

set_kb_item(name:"RHSA-2002-165", value:TRUE);
