#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14252);
 script_bugtraq_id(10852);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0415");
 
 name["english"] = "Fedora Core 1 2004-251: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-251 (kernel).

This kernel is vulnerable to a race condition in the 64-bit
file offset handling code.

The file offset pointer (f_pos) is changed during reading, writing, and
seeking through a file to point to the current position in a file.
The Linux kernel offers a 32bit and a 64bit API. Unfortunately the
value conversion between this two APIs as well as the access to the f_pos
pointer is defective.

An attacker, exploiting this flaw, would need local access to the
machine.  Upon successful exploitation, an attacker would be able
to read potentially confidential kernel memory.

Additionally, a number of issues were fixed in the USB serial code.

References:
http://www.isec.pl/vulnerabilities/isec-0016-procleaks.txt
http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0415

Solution : http://www.fedoranews.org/updates/FEDORA-2004-251.shtml

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
if ( rpm_check( reference:"kernel-source-2.4.22-1.2199.nptl", yank:".nptl", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.22-1.2199.nptl", yank:".nptl", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.22-1.2199.nptl", yank:".nptl", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-debuginfo-2.4.22-1.2199.nptl", yank:".nptl", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kernel-", release:"FC1") )
{
 set_kb_item(name:"CVE-2004-0415", value:TRUE);
}
