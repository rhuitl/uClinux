#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SuSE-SA:2003:045
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13813);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0886");
 
 name["english"] = "SuSE-SA:2003:045: hylafax";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SuSE-SA:2003:045 (hylafax).


Hylafax is an Open Source fax server which allows sharing of fax
equipment among computers by offering its service to clients by
a protocol similar to FTP.
The SuSE Security Team found a format bug condition during a code
review of the hfaxd server. It allows remote attackers to execute
arbitrary code as root. However, the bug can not be triggered in
hylafax' default configuration.

The 'capi4hylafax' packages also need to be updated as a dependency
where they are available.

After the update has been successfully applied the hfaxd server has
to be restarted by issuing the following command as root:

/etc/rc.d/hylafax restart

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2003_045_hylafax.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the hylafax package";
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
if ( rpm_check( reference:"hylafax-4.1-303", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-4.1-303", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-4.1.3-145", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"capi4hylafax-4.1.3-145", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-4.1.5-190", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"capi4hylafax-4.1.5-190", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-4.1.7-67", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"capi4hylafax-4.1.7-67", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"hylafax-", release:"SUSE7.3")
 || rpm_exists(rpm:"hylafax-", release:"SUSE8.0")
 || rpm_exists(rpm:"hylafax-", release:"SUSE8.1")
 || rpm_exists(rpm:"hylafax-", release:"SUSE8.2")
 || rpm_exists(rpm:"hylafax-", release:"SUSE9.0") )
{
 set_kb_item(name:"CVE-2003-0886", value:TRUE);
}
