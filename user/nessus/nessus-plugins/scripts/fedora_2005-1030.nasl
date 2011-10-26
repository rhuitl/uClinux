#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20098);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CAN-2005-2977");
 
 name["english"] = "Fedora Core 3 2005-1030: pam";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-1030 (pam).

PAM (Pluggable Authentication Modules) is a system security tool that
allows system administrators to set authentication policy without
having to recompile programs that handle authentication.

Update Information:

This update fixes a security bug in unix_chkpwd allowing
brute force attacks against passwords in /etc/shadow by a
regular user when SELinux is enabled.



Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the pam package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"pam-0.77-66.2.13", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pam-devel-0.77-66.2.13", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"pam-", release:"FC3") )
{
 set_kb_item(name:"CAN-2005-2977", value:TRUE);
}
