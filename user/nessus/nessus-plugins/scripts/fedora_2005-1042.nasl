#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20114);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CAN-2004-0079", "CVE-2003-0851", "CVE-2004-0079");
 
 name["english"] = "Fedora Core 3 2005-1042: openssl096b";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-1042 (openssl096b).

The OpenSSL toolkit provides support for secure communications between
machines. OpenSSL includes a certificate management tool and shared
libraries which provide various cryptographic algorithms and
protocols.

Update Information:

CAN-2004-0079, a remote crasher, was originally believed to
only affect versions of OpenSSL after 0.9.6b verified with
Codenomicon test suite (see pkt539.c). However we've had a
customer report that this affects 0.9.6b via a different
reproducer. This therefore affects the openssl096b
compat packages as shipped with FC-3.



Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openssl096b package";
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
if ( rpm_check( reference:"openssl096b-0.9.6b-21.42", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"openssl096b-", release:"FC3") )
{
 set_kb_item(name:"CAN-2004-0079", value:TRUE);
 set_kb_item(name:"CVE-2003-0851", value:TRUE);
 set_kb_item(name:"CVE-2004-0079", value:TRUE);
}
