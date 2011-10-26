#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:0008
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13773);
 script_bugtraq_id(6559);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0025");
 
 name["english"] = "SUSE-SA:2003:0008: imp";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2003:0008 (imp).


IMP is a well known PHP-based web-mail system.
Some SQL-injection vulnerabilities were found in  IMP 2.x that
allow an attacker to access the underlying database. No authentication
is needed to exploit this bug.
An attacker can gain access to protected information or, in conjunction
with PostgreSQL, execute shell commands remotely.

There is no temporary fix known. Please install the new packages from
our FTP servers.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2003_008_imp.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the imp package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"imp-2.2.6-247", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"imp-2.2.6-246", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"imp-2.2.6-248", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"imp-", release:"SUSE7.3")
 || rpm_exists(rpm:"imp-", release:"SUSE8.0")
 || rpm_exists(rpm:"imp-", release:"SUSE8.1") )
{
 set_kb_item(name:"CVE-2003-0025", value:TRUE);
}
