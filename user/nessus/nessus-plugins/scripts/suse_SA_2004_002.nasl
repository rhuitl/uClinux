#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SuSE-SA:2004:002
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13821);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SuSE-SA:2004:002: tcpdump";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SuSE-SA:2004:002 (tcpdump).


Tcpdump is a well known tool for administrators to analyze network
traffic.
There is a bug in the tcpdump code responsible for handling ISAKMP
messages. This bug allows remote attackers to destroy a current
tcpdump session by tricking the tcpdump program with evil ISAKMP
messages to enter an endless loop.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2004_02_tcpdump.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the tcpdump package";
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
if ( rpm_check( reference:"tcpdump-3.6.2-330", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.7.1-341", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.7.1-341", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.7.2-72", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
