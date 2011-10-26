#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:005
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13782);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "SUSE-SA:2003:005: susehelp";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2003:005 (susehelp).


During a code review of the susehelp package the SUSE Security Team
recognized that the security checks done by the susehelp CGI scripts are
insufficient.
Remote attackers can insert certain characters in CGI queries to the
susehelp system tricking it into executing arbitrary code as the 'wwwrun'
user. Please note that this is only a vulnerability if you have a web server
running and configured to allow access to the susehelp system by remote
sites.
We nevertheless recommend an update of this package. As a temporary
workaround you may un-install the susehelp package by issuing the following
command as root:

rpm -e --nodeps susehelp


Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2003_005_susehelp.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the susehelp package";
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
if ( rpm_check( reference:"susehelp-2002.09.05-51", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"susehelp-SLOD-2002.09.05-2", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
