#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19321);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2367");
 
 name["english"] = "Fedora Core 4 2005-655: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-655 (ethereal).

Ethereal is a network traffic analyzer for Unix-ish operating systems.

This package lays base for libpcap, a packet capture and filtering
library, contains command-line utilities, and contains plugins and
documentation for ethereal. A graphical user interface is packaged
separately to GTK+ package.


* Wed Jul 27 2005 Jindrich Novy <jnovy@redhat.com> 0.10.12-1.FC4.1
- update to 0.10.12
- package /usr/sbin/randpkt
- sync with cleanup patch (most of it applied upstream)
- the new release fixes CVE-2005-2361 up to CVE-2005-2367

* Mon May 30 2005 Radek Vokal <rvokal@redhat.com> 0.10.11-3
- ethereal cleanup, patch by Steve Grubb <sgrubb@redhat.com> (#159107)
- few more cleanups



Solution : http://fedoranews.org//mediawiki/index.php/Fedora_Core_4_Update:_ethereal-0.10.12-1.FC4.1
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
if ( rpm_check( reference:"ethereal-0.10.12-1.FC4.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.12-1.FC4.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"ethereal-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-2367", value:TRUE);
}
