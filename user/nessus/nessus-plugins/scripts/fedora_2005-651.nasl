#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19320);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2367");
 
 name["english"] = "Fedora Core 3 2005-651: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-651 (ethereal).

Ethereal is a network traffic analyzer for Unix-ish operating systems.

This package lays base for libpcap, a packet capture and filtering
library, contains command-line utilities, and contains plugins and
documentation for ethereal. A graphical user interface is packaged
separately to GTK+ package.


* Thu Jul 28 2005 Jindrich Novy 0.10.12-1.FC3.1
- update to 0.10.12
- package /usr/sbin/randpkt
- sync with cleanup patch (most of it applied upstream)
- the new release fixes CVE-2005-2361 up to CVE-2005-2367



Solution : http://www.fedoranews.org/blog/index.php?p=796
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal package";
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
if ( rpm_check( reference:"ethereal-0.10.12-1.FC3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.12-1.FC3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-debuginfo-0.10.12-1.FC3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"ethereal-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-2367", value:TRUE);
}
