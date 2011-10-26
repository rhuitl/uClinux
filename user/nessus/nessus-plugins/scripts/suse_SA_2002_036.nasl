#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2002:036
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13757);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0985");
 
 name["english"] = "SUSE-SA:2002:036: mod_php4";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2002:036 (mod_php4).


PHP is a well known and widely used web programming language.
If a PHP script runs in 'safe mode' several restrictions are applied
to it including limits on execution of external programs.

An attacker can pass shell meta-characters or sendmail(8) command line
options via the 5th argument (introduced in version 4.0.5) of the mail()
function to execute shell commands or control the behavior of sendmail(8).

The CRLF injection vulnerabilities in fopen(), file(), header(), ...
allow an attacker to bypass ACLs or trigger cross-side scripting.

The mod_php4 package is not installed by default.
A temporary fix is not known.

Please note, that the following packages were rebuild too:
- mod_php4-core
- mod_php4-aolserver
- mod_php4-devel
- mod_php4-servlet
- mod_php4-roxen

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2002_036_modphp4.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mod_php4 package";
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
if ( rpm_check( reference:"mod_php4-4.0.4pl1-135", release:"SUSE7.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-4.0.4pl1-142", release:"SUSE7.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-4.0.6-192", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-4.0.6-193", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-4.1.0-257", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"mod_php4-", release:"SUSE7.0")
 || rpm_exists(rpm:"mod_php4-", release:"SUSE7.1")
 || rpm_exists(rpm:"mod_php4-", release:"SUSE7.2")
 || rpm_exists(rpm:"mod_php4-", release:"SUSE7.3")
 || rpm_exists(rpm:"mod_php4-", release:"SUSE8.0") )
{
 set_kb_item(name:"CVE-2002-0985", value:TRUE);
}
