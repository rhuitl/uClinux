#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:035
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13803);
 script_bugtraq_id(8485);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0688");
 
 name["english"] = "SUSE-SA:2003:035: sendmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2003:035 (sendmail).


The well known and widely used MTA sendmail is vulnerable to a
remote denial-of-service attack in version 8.12.8 and earlier (but not
before 8.12). The bug exists in the DNS map code. This feature is
enabled by specifying FEATURE(`enhdnsbl').
When sendmail receives an invalid DNS response it tries to call free(3)
on random data which results in a process crash.

After your system was updated you have to restart your sendmail daemon
to make the update effective.

There is no known workaround for this vulnerability other than using a
different MTA.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2003_035_sendmail.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the sendmail package";
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
if ( rpm_check( reference:"sendmail-8.12.3-76", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"uucp-1.06.1-931", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.12.6-147", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"uucp-1.06.1-931", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.12.7-73", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"uucp-1.06.1-931", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"sendmail-", release:"SUSE8.0")
 || rpm_exists(rpm:"sendmail-", release:"SUSE8.1")
 || rpm_exists(rpm:"sendmail-", release:"SUSE8.2") )
{
 set_kb_item(name:"CVE-2003-0688", value:TRUE);
}
