#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13662);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2003-0542");
 
 name["english"] = "Fedora Core 1 2003-004: httpd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2003-004 (httpd).

Apache is a powerful, full-featured, efficient, and freely-available
Web server. Apache is also the most popular Web server on the
Internet.

Update Information:

This update includes the latest stable release of Apache httpd 2.0,
including a fix for the security issue CVE CVE-2003-0542, a buffer
overflow in the parsing of configuration files.


Solution : http://www.fedoranews.org/updates/FEDORA-2003-004.shtml
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
if ( rpm_check( reference:"httpd-2.0.48-1.2", prefix:"httpd-", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"httpd-", release:"FC1") )
{
 set_kb_item(name:"CVE-2003-0542", value:TRUE);
}
