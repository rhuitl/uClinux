#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:077
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14060);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0504", "CVE-2003-0582");
 
 name["english"] = "MDKSA-2003:077: phpgroupware";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:077 (phpgroupware).


Several vulnerabilities were discovered in all versions of phpgroupware prior to
0.9.14.006. This latest version fixes an exploitable condition in all versions
that can be exploited remotely without authentication and can lead to arbitrary
code execution on the web server. This vulnerability is being actively
exploited.
Version 0.9.14.005 fixed several other vulnerabilities including cross-site
scripting issues that can be exploited to obtain sensitive information such as
authentication cookies.
This update provides the latest stable version of phpgroupware and all users are
encouraged to update immediately. In addition, you should also secure your
installation by including the following in your Apache configuration files:
Order allow,deny Deny from all


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:077
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the phpgroupware package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"phpgroupware-0.9.14.006-0.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"phpgroupware-0.9.14.006-0.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"phpgroupware-0.9.14.006-0.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"phpgroupware-", release:"MDK8.2")
 || rpm_exists(rpm:"phpgroupware-", release:"MDK9.0")
 || rpm_exists(rpm:"phpgroupware-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0504", value:TRUE);
 set_kb_item(name:"CVE-2003-0582", value:TRUE);
}
