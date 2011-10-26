#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13709);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "Fedora Core 2 2004-137: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-137 (kernel).

The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

Update Information:

An updated kernel is available that brings the kernel to the 2.6.7-rc3 base
level. This new kernel provides a significant number of bug fixes and
improvements for USB, the keyboard/mouse subsystem and the VM. This kernel
also fixes the high profile bugs about not working on VIA C3 processors
(#120685) and Asus P4P800 motherboards (#121819). In this new kernel
firewire no longer oopses during boot and has been re-enabled, however we
consider firewire support still somewhat experimental and recommend
extensive testing before using firewire in a production environment.

This kernel also contains the enhancements series from Al Viro that enables
the Sparse source code checking tool to check for a certain class kernel
bugs. This class of bugs can lead to privilege escalation vulnerabilities,
and fixes for all such bugs that were found with Sparse and these patches
are included in this erratum.


In addition to these bugfixes, the x86 kernel-smp subpackage now also
contains support for the 'NX' feature that is present in current AMD
Athlon64/Opteron processors and for which support has been announced by
Intel, VIA and Transmeta for future processors.


Solution : http://www.fedoranews.org/updates/FEDORA-2004-137.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kernel package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kernel-2.6.6-1.427", prefix:"kernel-", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
