#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:036
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13804);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2003:036: pam_smb";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2003:036 (pam_smb).


The PAM module (and server) pam_smb allows users of Linux systems to
be authenticated by querying an NT server.
Dave Airlie <airlied@samba.org> informed us about a bug in the
authentication code of pam_smb that allows a remote attacker to gain
access to a system using pam_smb by issuing a too long password string.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2003_036_pam_smb.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the pam_smb package";
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
if ( rpm_check( reference:"pam_smb-1.1.6-500", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pam_smb-1.1.6-501", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pam_smb-1.1.6-500", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pam_smb-1.1.6-500", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pam_smb-1.1.6-501", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
