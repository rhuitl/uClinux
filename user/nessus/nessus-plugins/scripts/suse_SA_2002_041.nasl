#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2002:041
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13762);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2002:041: perl-MailTools";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2002:041 (perl-MailTools).


The SUSE Security Team reviewed critical Perl modules, including the
Mail::Mailer package. This package contains a security hole which allows
remote attackers to execute arbitrary commands in certain circumstances.
This is due to the usage of mailx as default mailer which allows commands
to be embedded in the mail body.
Vulnerable to this attack are custom auto reply programs or spam filters
which use Mail::Mailer directly or indirectly.


Solution : http://www.suse.de/security/2002_041_perl_mailtools.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the perl-MailTools package";
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
if ( rpm_check( reference:"perl-MailTools-1.1401-188", release:"SUSE7.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-MailTools-1.1401-187", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-MailTools-1.1401-187", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-MailTools-1.42-120", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-MailTools-1.47-29", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
