#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19728);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2700", "CVE-2005-2728");
 
 name["english"] = "Fedora Core 4 2005-849: httpd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-849 (httpd).

The Apache HTTP Server is a powerful, full-featured, efficient, and
freely-available Web server. The Apache HTTP Server is also the
most popular Web server on the Internet.

Update Information:

This update includes two security fixes. An issue was
discovered in mod_ssl where 'SSLVerifyClient require' would
not be honoured in location context if the virtual host had
'SSLVerifyClient optional' configured (CVE-2005-2700). An
issue was discovered in memory consumption of the byterange
filter for dynamic resources such as PHP or CGI script
(CVE-2005-2728).


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the httpd package";
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
if ( rpm_check( reference:"httpd-2.0.54-10.2", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.0.54-10.2", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-manual-2.0.54-10.2", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.0.54-10.2", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"httpd-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-2700", value:TRUE);
 set_kb_item(name:"CVE-2005-2728", value:TRUE);
}
