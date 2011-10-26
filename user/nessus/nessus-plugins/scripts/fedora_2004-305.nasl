#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14717);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0808");
 
 name["english"] = "Fedora Core 2 2004-305: samba";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-305 (samba).

Samba is the protocol by which a lot of PC-related machines share
files, printers, and other information (such as lists of available
files and printers). The Windows NT, OS/2, and Linux operating systems
support this natively, and add-on packages can enable the same thing
for DOS, Windows, VMS, UNIX of all kinds, MVS, and more. This package
provides an SMB server that can be used to provide network services to
SMB (sometimes called 'Lan Manager') clients. Samba uses NetBIOS over
TCP/IP (NetBT) protocols and does NOT need the NetBEUI (Microsoft Raw
NetBIOS frame) protocol.

Update Information:

This update corrects two Denial-of-Service attacks against
Samba-3.0.6.

This update may also fix other problems some people experienced with          
Samba-3.0.6.


Solution : http://www.fedoranews.org/updates/FEDORA-2004-305.shtml
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
if ( rpm_check( reference:"samba-3.0.7-2.FC2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-3.0.7-2.FC2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-common-3.0.7-2.FC2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-swat-3.0.7-2.FC2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-debuginfo-3.0.7-2.FC2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"samba-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0808", value:TRUE);
}
