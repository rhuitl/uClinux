#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14807);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0747", "CVE-2004-0748", "CVE-2004-0809", "CVE-2004-0811");
 
 name["english"] = "Fedora Core 2 2004-313: httpd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-313 (httpd).

Apache is a powerful, full-featured, efficient, and freely-available
Web server. Apache is also the most popular Web server on the
Internet.


This update includes the latest stable release of Apache httpd 2.0,
including fixes for possible denial of service issues in mod_ssl
(CVE-2004-0751, CVE-2004-0747) and mod_dav_fs (CVE-2004-0809), and a
privilege elevation attack for local users (CVE-2004-0747).

Note that these packages do also contain the fix for a regression in
Satisfy handling in the 2.0.51 release (CVE-2004-0811).



Solution : http://www.fedoranews.org/updates/FEDORA-2004-313.shtml
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
if ( rpm_check( reference:"httpd-2.0.51-2.7", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.0.51-2.7", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-manual-2.0.51-2.7", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.0.51-2.7", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-debuginfo-2.0.51-2.7", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"httpd-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0747", value:TRUE);
 set_kb_item(name:"CVE-2004-0748", value:TRUE);
 set_kb_item(name:"CVE-2004-0809", value:TRUE);
 set_kb_item(name:"CVE-2004-0811", value:TRUE);
}
