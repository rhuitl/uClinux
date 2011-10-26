#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15734);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0885", "CVE-2004-0942");
 
 name["english"] = "Fedora Core 2 2004-420: httpd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-420 (httpd).

Apache is a powerful, full-featured, efficient, and freely-available
Web server. Apache is also the most popular Web server on the
Internet.


This update includes the fixes for an issue in mod_ssl which could
lead to a bypass of an SSLCipherSuite setting in directory or location
context (CVE CVE-2004-0885), and a memory consumption denial of
service issue in the handling of request header lines (CVE
CVE-2004-0942).



Solution : http://www.fedoranews.org/blog/index.php?p=71
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
if ( rpm_check( reference:"httpd-2.0.51-2.9", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.0.51-2.9", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-manual-2.0.51-2.9", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.0.51-2.9", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-debuginfo-2.0.51-2.9", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"httpd-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0885", value:TRUE);
 set_kb_item(name:"CVE-2004-0942", value:TRUE);
}
