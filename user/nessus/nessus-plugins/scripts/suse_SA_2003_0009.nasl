#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:0009
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13774);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-1396");
 
 name["english"] = "SUSE-SA:2003:0009: mod_php4";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2003:0009 (mod_php4).


The Apache module mod_php4 supports the widely used Web scripting
language PHP.
Under some special circumstances a buffer overflow can be triggered
in mod_php4's wordwrap() function. This buffer overflow can be used
to overwrite heap memory and possibly can lead to remote system
compromise.
Just mod_php4 versions greater than 4.1.2 and less than 4.3.0
are vulnerable. This affects SUSE LINUX 8.1 and all SUSE LINUX
Enterprise Server 8 based products.

There is no temporary fix known. Please install the new packages from
our FTP servers.

After updating the mod_php4 module has to be reloaded by Apache.
This can be done by restarting the apache webserver using the following
command as root:
rcapache restart

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2003_009_mod_php4.html
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
if ( rpm_check( reference:"mod_php4-4.2.2-168", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-core-4.2.2-168", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-devel-4.2.2-168", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-servlet-4.2.2-168", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-aolserver-4.2.2-168", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"mod_php4-", release:"SUSE8.1") )
{
 set_kb_item(name:"CVE-2002-1396", value:TRUE);
}
