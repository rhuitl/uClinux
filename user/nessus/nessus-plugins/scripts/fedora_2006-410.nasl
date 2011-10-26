#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21250);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-1724", "CVE-2006-1728", "CVE-2006-1729", "CVE-2006-1739", "CVE-2006-1740", "CVE-2006-1741", "CVE-2006-1742", "CVE-2006-1790");
 
 name["english"] = "Fedora Core 4 2006-410: firefox";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2006-410 (firefox).

Mozilla Firefox is an open-source web browser, designed for standards
compliance, performance and portability.

Update Information:

Several bugs were found in the way Firefox processes
malformed javascript. A malicious web page could modify the
content of a different open web page, possibly stealing
sensitive information or conducting a cross-site scripting
attack. (CVE-2006-1731, CVE-2006-1732, CVE-2006-1741)

Several bugs were found in the way Firefox processes certain
javascript actions. A malicious web page could execute
arbitrary javascript instructions with the permissions of
'chrome', allowing the page to steal sensitive information
or install browser malware. (CVE-2006-1727, CVE-2006-1728,
CVE-2006-1733, CVE-2006-1734, CVE-2006-1735, CVE-2006-1742)

Several bugs were found in the way Firefox processes
malformed web pages. A carefully crafted malicious web page
could cause the execution of arbitrary code as the user
running Firefox. (CVE-2006-0749, CVE-2006-1724,
CVE-2006-1730, CVE-2006-1737, CVE-2006-1738, CVE-2006-1739,
CVE-2006-1790)

A bug was found in the way Firefox displays the secure site
icon. If a browser is configured to display the non-default
secure site modal warning dialog, it may be possible to
trick a user into believing they are viewing a secure site.
(CVE-2006-1740)

A bug was found in the way Firefox allows javascript
mutation events on 'input' form elements. A malicious web
page could be created in such a way that when a user submits
a form, an arbitrary file could be uploaded to the attacker.
(CVE-2006-1729)


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the firefox package";
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
if ( rpm_check( reference:"firefox-1.0.8-1.1.fc4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"firefox-", release:"FC4") )
{
 set_kb_item(name:"CVE-2006-1724", value:TRUE);
 set_kb_item(name:"CVE-2006-1728", value:TRUE);
 set_kb_item(name:"CVE-2006-1729", value:TRUE);
 set_kb_item(name:"CVE-2006-1739", value:TRUE);
 set_kb_item(name:"CVE-2006-1740", value:TRUE);
 set_kb_item(name:"CVE-2006-1741", value:TRUE);
 set_kb_item(name:"CVE-2006-1742", value:TRUE);
 set_kb_item(name:"CVE-2006-1790", value:TRUE);
}
