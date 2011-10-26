#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13734);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0488", "CVE-2004-0493");
 
 name["english"] = "Fedora Core 1 2004-203: httpd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-203 (httpd).

Apache is a powerful, full-featured, efficient, and freely-available
Web server. Apache is also the most popular Web server on the
Internet.

Update Information:

This update includes the latest stable release of Apache httpd 2.0,
including security fixes for a remotely triggerable memory leak
(CVE CVE-2004-0493), and a buffer overflow in mod_ssl which can be
triggered only by a (trusted) client certificate with a long subject
DN field (CVE CVE-2004-0488).



Solution : http://www.fedoranews.org/updates/FEDORA-2004-203.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the httpd package";
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
if ( rpm_check( reference:"httpd-2.0.50-1.0", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.0.50-1.0", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-manual-2.0.50-1.0", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.0.50-1.0", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-debuginfo-2.0.50-1.0", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"httpd-", release:"FC1") )
{
 set_kb_item(name:"CVE-2004-0488", value:TRUE);
 set_kb_item(name:"CVE-2004-0493", value:TRUE);
}
