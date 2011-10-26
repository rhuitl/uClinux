#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20757);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2970", "CVE-2005-3352", "CVE-2005-3357");
 
 name["english"] = "Fedora Core 4 2006-052: httpd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2006-052 (httpd).

The Apache HTTP Server is a powerful, full-featured, efficient, and
freely-available Web server. The Apache HTTP Server is also the
most popular Web server on the Internet.

Update Information:

This update includes fixes for three security issues in the
Apache HTTP Server.

A memory leak in the worker MPM could allow remote attackers
to cause a denial of service (memory consumption) via
aborted connections, which prevents the memory for the
transaction pool from being reused for other connections.
The Common Vulnerabilities and Exposures project assigned
the name CVE-2005-2970 to this issue. This vulnerability
only affects users who are using the non-default worker MPM.

A flaw in mod_imap when using the Referer directive with
image maps was discovered. With certain site configurations,
a remote attacker could perform a cross-site scripting
attack if a victim can be  forced to visit a malicious URL
using certain web browsers. (CVE-2005-3352)

A NULL pointer dereference flaw in mod_ssl was discovered
affecting server configurations where an SSL virtual host is
configured with access control and a custom 400 error
document. A remote attacker could send a carefully
crafted request to trigger this issue which would lead to a
crash. This crash would only be a denial of service if using
the non-default worker MPM. (CVE-2005-3357)



Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the httpd package";
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
if ( rpm_check( reference:"httpd-2.0.54-10.3", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.0.54-10.3", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.0.54-10.3", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"httpd-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-2970", value:TRUE);
 set_kb_item(name:"CVE-2005-3352", value:TRUE);
 set_kb_item(name:"CVE-2005-3357", value:TRUE);
}
