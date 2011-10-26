#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13684);
 script_bugtraq_id(8970);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0851", "CVE-2004-0081");
 
 name["english"] = "Fedora Core 1 2004-095: openssl";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-095 (openssl).

The OpenSSL toolkit provides support for secure communications between
machines. OpenSSL includes a certificate management tool and shared
libraries which provide various cryptographic algorithms and
protocols.

Update Information:

This update includes OpenSSL packages to fix two security issues
affecting OpenSSL 0.9.7a which allow denial of service attacks; CVE
CVE-2004-0079 and CVE CVE-2003-0851.

Also included are updates for the OpenSSL 0.9.6 and 0.9.6b
compatibility libraries included in Fedora Core 1, fixing a separate
issue which could also lead to a denial of service attack; CVE
CVE-2004-0081.



Solution : http://www.fedoranews.org/updates/FEDORA-2004-095.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openssl package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"openssl-0.9.7a-33.10", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.7a-33.10", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-perl-0.9.7a-33.10", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl-debuginfo-0.9.7a-33.10", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl096-0.9.6-26", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl096-debuginfo-0.9.6-26", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl096b-0.9.6b-18", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openssl096b-debuginfo-0.9.6b-18", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"openssl-", release:"FC1") )
{
 set_kb_item(name:"CVE-2003-0851", value:TRUE);
 set_kb_item(name:"CVE-2004-0081", value:TRUE);
}
