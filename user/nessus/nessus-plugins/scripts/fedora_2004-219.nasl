#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13738);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0633", "CVE-2004-0634", "CVE-2004-0635");
 
 name["english"] = "Fedora Core 1 2004-219: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-219 (ethereal).

Ethereal is a network traffic analyzer for Unix-ish operating systems.

This package lays base for libpcap, a packet capture and filtering
library, contains command-line utilities, contains plugins and
documentation for ethereal. A graphical user interface is packaged
separately to GTK+ package.

Update Information:

 Issues have been discovered in the following protocol dissectors:

    * The iSNS dissector could make Ethereal abort in some cases.
(0.10.3 - 0.10.4) CVE-2004-0633
    * SMB SID snooping could crash if there was no policy name for a
handle. (0.9.15 - 0.10.4) CVE-2004-0634
    * The SNMP dissector could crash due to a malformed or missing
community string. (0.8.15 - 0.10.4) CVE-2004-0635

Impact:

It may be possible to make Ethereal crash or run arbitrary code by
injecting a purposefully malformed packet onto the wire or by convincing
someone to read a malformed packet trace file.

Resolution:

Upgrade to 0.10.5.

If you are running a version prior to 0.10.5 and you cannot upgrade, you
can disable all of the protocol dissectors listed above by selecting
Analyze->Enabled Protocols... and deselecting them from the list. For
SMB, you can alternatively disable SID snooping in the SMB protocol
preferences. However, it is strongly recommended that you upgrade to
0.10.5.


Solution : http://www.fedoranews.org/updates/FEDORA-2004-219.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal package";
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
if ( rpm_check( reference:"ethereal-0.10.5-0.1.1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.5-0.1.1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-debuginfo-0.10.5-0.1.1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"ethereal-", release:"FC1") )
{
 set_kb_item(name:"CVE-2004-0633", value:TRUE);
 set_kb_item(name:"CVE-2004-0634", value:TRUE);
 set_kb_item(name:"CVE-2004-0635", value:TRUE);
}
