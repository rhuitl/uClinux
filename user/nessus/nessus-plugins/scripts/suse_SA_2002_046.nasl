#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2002:046
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13767);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2002:046: pine";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2002:046 (pine).


Pine, Program for Internet News and Email, is a well known and widely
used eMail client.
While parsing and escaping characters of eMail addresses pine does not
allocate enough memory for storing the escaped mailbox part of an
address. This results in a buffer overflow on the heap that will make
pine crash. The offending eMail can just be deleted manually or by using
another mail user agent.

A possible temporary workaround is to filter the respective header
lines by a mail delivery agent (such as procmail).

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2002_046_pine.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the pine package";
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
if ( rpm_check( reference:"pine-4.33-263", release:"SUSE7.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"pine-4.33-266", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"pine-4.33-266", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"pine-4.44-222", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"pine-4.44-224", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
