#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19630);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1177", "CVE-2005-0202");
 
 name["english"] = "Fedora Core 3 2005-242: mailman";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-242 (mailman).

Mailman is software to help manage email discussion lists, much like
Majordomo and Smartmail. Unlike most similar products, Mailman gives
each mailing list a webpage, and allows users to subscribe,
unsubscribe, etc. over the Web. Even the list manager can administer
his or her list entirely from the Web. Mailman also integrates most
things people want to do with mailing lists, including archiving, mail
<-> news gateways, and so on.

Documentation can be found in: /usr/share/doc/mailman-2.1.5

When the package has finished installing, you will need to perform some
additional installation steps, these are described in:
/usr/share/doc/mailman-2.1.5/INSTALL.REDHAT

Update Information:

A cross-site scripting (XSS) flaw in the driver script of mailman
prior to version 2.1.5 could allow remote attackers to execute scripts
as other web users. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-1177 to this issue.

Users of mailman should update to this erratum package, which corrects
this issue by turning on STEALTH_MODE by default and using
Utils.websafe() to quote the html.

In addition this version of the rpm includes a utility script in
/usr/share/doc/mailman-*/contrib/migrate-fhs that can be run if the
user has installed an FC3 or FC4 mailman rpm over an older non-FHS
compliant mailman installation. The script will aid in moving the file
locations from the old directory structure to the new FHS mailman
directory structure that are present in FC3, FC4, and RHEL4. Users who
have installed mailman originally from FC3, FC4 or RHEL4 will not need
to migration any file locations.



Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mailman package";
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
if ( rpm_check( reference:"mailman-2.1.5-32.fc3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"mailman-", release:"FC3") )
{
 set_kb_item(name:"CVE-2004-1177", value:TRUE);
 set_kb_item(name:"CVE-2005-0202", value:TRUE);
}
