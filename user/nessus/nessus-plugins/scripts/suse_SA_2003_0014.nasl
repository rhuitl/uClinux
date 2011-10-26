#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:0014
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13778);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2003:0014: lprold";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2003:0014 (lprold).


The lprm command of the printing package lprold shipped till SUSE 7.3
contains a buffer overflow. This buffer overflow can be exploited by
a local user, if the printer system is set up correctly, to gain root
privileges.
lprold is installed as default package and has the setuid bit set.

As a temporary workaround you can disable the setuid bit of lprm by
executing the following tasks as root:
- add '/usr/bin/lprm  root.root 755' to /etc/permissions.local
- run 'chkstat -set /etc/permissions.local'
Another way would be to just allow trusted users to run lprm by
executing the following tasks as root:
- add '/usr/bin/lprm  root.trusted 4750' to /etc/permissions.local
- run 'chkstat -set /etc/permissions.local'

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2003_014_lprold.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the lprold package";
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
if ( rpm_check( reference:"lprold-3.0.48-407", release:"SUSE7.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"lprold-3.0.48-407", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"lprold-3.0.48-408", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
