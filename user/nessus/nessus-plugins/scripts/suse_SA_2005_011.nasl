#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:011
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17238);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0490");
 
 name["english"] = "SUSE-SA:2005:011: curl";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:011 (curl).


infamous41md@hotpop.com reported a vulnerability in libcurl, the
HTTP/FTP retrieval library. This library is used by lots of programs,
including YaST2 and PHP4.

The NTLM authorization in curl had a buffer overflow in the base64
decoding which allows a remote attacker using a prepared remote
server to execute code for the user using curl.

The Kerberos authorization has a similar bug, but is not compiled
in on SUSE Linux.

This is tracked by the Mitre CVE ID CVE-2005-0490.


Solution : http://www.suse.de/security/advisories/2005_11_curl.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the curl package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"curl-7.11.0-39.4", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"curl-devel-7.11.0-39.4", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"curl-7.12.0-2.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"curl-devel-7.12.0-2.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"curl-", release:"SUSE9.1")
 || rpm_exists(rpm:"curl-", release:"SUSE9.2") )
{
 set_kb_item(name:"CVE-2005-0490", value:TRUE);
}
