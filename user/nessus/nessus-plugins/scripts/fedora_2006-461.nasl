#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21294);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-1932", "CVE-2006-1933", "CVE-2006-1934", "CVE-2006-1935", "CVE-2006-1936", "CVE-2006-1937", "CVE-2006-1938", "CVE-2006-1939", "CVE-2006-1940");
 
 name["english"] = "Fedora Core 4 2006-461: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2006-461 (ethereal).

Ethereal is a network traffic analyzer for Unix-ish operating systems.

This package lays base for libpcap, a packet capture and filtering
library, contains command-line utilities, contains plugins and
documentation for ethereal. A graphical user interface is packaged
separately to GTK+ package.

Many security vulnerabilities have been fixed since the
previous release.

Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"ethereal-0.99.0-fc4.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"ethereal-", release:"FC4") )
{
 set_kb_item(name:"CVE-2006-1932", value:TRUE);
 set_kb_item(name:"CVE-2006-1933", value:TRUE);
 set_kb_item(name:"CVE-2006-1934", value:TRUE);
 set_kb_item(name:"CVE-2006-1935", value:TRUE);
 set_kb_item(name:"CVE-2006-1936", value:TRUE);
 set_kb_item(name:"CVE-2006-1937", value:TRUE);
 set_kb_item(name:"CVE-2006-1938", value:TRUE);
 set_kb_item(name:"CVE-2006-1939", value:TRUE);
 set_kb_item(name:"CVE-2006-1940", value:TRUE);
}
