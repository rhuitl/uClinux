#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:041
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13809);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2003:041: lsh";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2003:041 (lsh).


LSH is the GNU implementation of SSH and can be seen as an alternative
to OpenSSH.
Recently various remotely exploitable buffer overflows have been
reported in LSH. These allow attackers to execute arbitrary code as root
on un-patched systems.
LSH is not installed by default on SUSE LINUX. An update is therefore
only recommended if you run LSH.
Maintained SUSE products are not affected by this bug as LSH is not
packaged on maintained products such as the Enterprise Server.

For the updates to take effect execute the following command as root:

/usr/sbin/rclshd restart

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2003_041_lsh.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the lsh package";
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
if ( rpm_check( reference:"lsh-1.3.5-188", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"lsh-1.4.2-73", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"lsh-1.5-114", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
