#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20078);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CAN-2005-2973");
 
 name["english"] = "Fedora Core 4 2005-1013: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-1013 (kernel).

The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.


* Wed Oct 19 2005 Dave Jones <davej redhat com> [2.6.13-1.1532_FC4]
- Fix CAN-2005-2973 (ipv6 infinite loop)
- Disable ACPI burst again, it's still problematic.
- Update to the final upstream variant of the IDE/SATA fix.

* Sun Oct 16 2005 Dave Jones <davej redhat com> [2.6.13-1.1531_FC4]
- Stop IDE claiming legacy ports before libata in combined mode.

* Sun Oct 16 2005 Dave Jones <davej redhat com> [2.6.13-1.1530_FC4]
- Enable ACPI EC burst.
- Reenable change of timesource default.

* Tue Oct 11 2005 Dave Jones <davej redhat com> [2.6.13-1.1529_FC4]
- 2.6.13.4

* Thu Oct  6 2005 Dave Jones <davej redhat com>
- Fix information leak in orinoco driver.

* Wed Oct  5 2005 Dave Jones <davej redhat com>
- Further fixing to the 8139too suspend/resume problem.

* Mon Oct  3 2005 Dave Jones <davej redhat com> [2.6.13-1.1528_FC4]
- 2.6.13.3

* Sun Oct  2 2005 Dave Jones <davej redhat com> [2.6.13-1.1527_FC4]
- Disable debug messages in w83781d sensor driver. (#169695)
- Re-add a bunch of patches that got accidentally dropped in last update.
- Fix suspend/resume with 8139too
- Fix usbhid/wireless security lock clash (#147479)
- Missing check condition in ide scsi (#160868)
- Fix nosense error with transcend usb keys (#162559)
- Fix sk98lin vpd problem. (#136158)
- Fix IDE floppy eject. (#158548)

* Fri Sep 30 2005 Dave Jones <davej redhat com>
- irda-driver smsc-ircc2 needs pnp-functionality. (#153970)
- Reenable /proc/acpi/sleep (#169650)
- Silence some selinux messages. (#167852)




Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kernel package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kernel-2.6.13-1.1532_FC4", prefix:"kernel-", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kernel-", release:"FC4") )
{
 set_kb_item(name:"CAN-2005-2973", value:TRUE);
}
