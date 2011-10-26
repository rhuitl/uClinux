#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16026);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1154");
 
 name["english"] = "Fedora Core 2 2004-561: samba";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-561 (samba).

Samba is the suite of programs by which a lot of PC-related machines
share files, printers, and other information (such as lists of
available
files and printers). The Windows NT, OS/2, and Linux operating systems
support this natively, and add-on packages can enable the same thing
for DOS, Windows, VMS, UNIX of all kinds, MVS, and more. This package
provides an SMB server that can be used to provide network services to
SMB (sometimes called 'Lan Manager') clients. Samba uses NetBIOS over
TCP/IP (NetBT) protocols and does NOT need the NetBEUI (Microsoft Raw
NetBIOS frame) protocol.


* Fri Dec 17 2004 Jay Fenlason 3.0.10-1.fc2

- New upstream release that closes CVE-2004-1154 bz#142544
- Include the -64bit patch from Nalin. This closes bz#142873
- Update the -logfiles patch to work with 3.0.10
- Create /var/run/winbindd and make it part of the -common rpm to
close
bz#142242
- move /var/log/samba to -common



Solution : http://www.fedoranews.org/blog/index.php?p=215
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the samba package";
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
if ( rpm_check( reference:"samba-3.0.10-1.fc2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-3.0.10-1.fc2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-common-3.0.10-1.fc2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-swat-3.0.10-1.fc2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-debuginfo-3.0.10-1.fc2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"samba-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-1154", value:TRUE);
}
