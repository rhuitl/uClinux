#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2004:022
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13838);
 script_bugtraq_id(10780);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2004-0600", "CVE-2004-0686");
 
 name["english"] = "SUSE-SA:2004:022: samba";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2004:022 (samba).


The Samba Web Administration Tool (SWAT) was found vulnerable to
a buffer overflow in its base64 code. This buffer overflow can possibly
be exploited remotely before any authentication took place to execute
arbitrary code.
The same piece of vulnerable code was also used in ldapsam passdb and
in the ntlm_auth tool.
This vulnerability only exists on Samba 3.0.2 to 3.0.4.

Another buffer overflow was found in Samba 3.0.0 and later, as well as
in Samba 2.2.x. This overflow exists in the hash code of the mangling
method (smb.conf: mangling method = hash), the default uses hash2 which
is not vulnerable.

There is no temporary workaround known. The first proof-of-concept
exploits were seen on public mailing lists.

After the installation was successfully completed please restart the
samba daemon.
/usr/sbin/rcsmb restart

SWAT is called by inetd/xinetd. Therefore it is sufficient to kill all
running instances of SWAT only.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2004_22_samba.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the samba package";
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
if ( rpm_check( reference:"samba-2.2.8a-218", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.8a-218", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-vscan-0.3.2a-271", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-2.2.8a-220", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.8a-220", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-vscan-0.3.2a-273", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-doc-2.2.8a-220", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsmbclient-2.2.8a-220", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsmbclient-devel-2.2.8a-220", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-2.2.8a-220", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.8a-220", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsmbclient-2.2.8a-220", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsmbclient-devel-2.2.8a-220", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-3.0.4-1.27", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-3.0.4-1.27", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-pdb-3.0.4-1.27", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-python-3.0.4-1.27", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-vscan-0.3.4-83.30", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-winbind-3.0.4-1.27", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-doc-3.0.4-1.12", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsmbclient-3.0.4-1.27", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libsmbclient-devel-3.0.4-1.27", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"samba-", release:"SUSE8.1")
 || rpm_exists(rpm:"samba-", release:"SUSE8.2")
 || rpm_exists(rpm:"samba-", release:"SUSE9.0")
 || rpm_exists(rpm:"samba-", release:"SUSE9.1") )
{
 set_kb_item(name:"CVE-2004-0600", value:TRUE);
 set_kb_item(name:"CVE-2004-0686", value:TRUE);
}
