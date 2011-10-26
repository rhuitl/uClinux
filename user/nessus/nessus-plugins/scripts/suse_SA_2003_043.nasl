#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:043
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13811);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0543", "CVE-2003-0544", "CVE-2003-0545");
 
 name["english"] = "SUSE-SA:2003:043: openssl";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2003:043 (openssl).


OpenSSL is an implementation of the Secure Socket Layer (SSL v2/3)
and Transport Layer Security (TLS v1) protocol.
While checking the openssl implementation with a tool-kit from NISCC
several errors were revealed most are ASN.1 encoding issues that
causes a remote denial-of-service attack on the server side and
possibly lead to remote command execution.

There are two problems with ASN.1 encoding that can be triggered either
by special ASN.1 encodings or by special ASN.1 tags.

In debugging mode public key decoding errors can be ignored but
also lead to a crash of the verify code if an invalid public key
was received from the client.

A mistake in the SSL/TLS protocol handling will make the server accept
client certificates even if they are not requested. This bug makes
it possible to exploit the bugs mentioned above even if client
authentication is disabled.

There is not other solution known to this problem then updating to the
current version from our FTP servers.

To make this update effective, restart all servers using openssl please.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2003_043_openssl.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openssl package";
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
if ( rpm_check( reference:"openssl-0.9.6a-83", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-doc-0.9.6a-83", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.6a-83", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6b-158", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-doc-0.9.6b-158", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.6b-158", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6c-86", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-doc-0.9.6c-86", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.6c-86", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6g-99", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-doc-0.9.6g-99", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.6g-99", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6i-19", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-doc-0.9.6i-19", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.6i-19", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7b-71", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-doc-0.9.7b-71", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.7b-71", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"openssl-", release:"SUSE7.2")
 || rpm_exists(rpm:"openssl-", release:"SUSE7.3")
 || rpm_exists(rpm:"openssl-", release:"SUSE8.0")
 || rpm_exists(rpm:"openssl-", release:"SUSE8.1")
 || rpm_exists(rpm:"openssl-", release:"SUSE8.2")
 || rpm_exists(rpm:"openssl-", release:"SUSE9.0") )
{
 set_kb_item(name:"CVE-2003-0543", value:TRUE);
 set_kb_item(name:"CVE-2003-0544", value:TRUE);
 set_kb_item(name:"CVE-2003-0545", value:TRUE);
}
