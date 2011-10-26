#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:005
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13990);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2003:005: leafnode";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:005 (leafnode).


A vulnerability was discovered by Jan Knutar in leafnode that Mark Brown pointed
out could be used in a Denial of Service attack. This vulnerability causes
leafnode to go into an infinite loop with 100% CPU use when an article that has
been crossposed to several groups, one of which is the prefix of another, is
requested by it's Message-ID.
This vulnerability was introduced in 1.9.20 and fixed upstream in version
1.9.30. Only Mandrake Linux 9.0 is affected by this, but version 1.9.19 (which
shipped with Mandrake Linux 8.2) is receiving an update due to critical bugs in
it that can corrupt parts of its news spool under certain circumstances.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:005
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the leafnode package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"leafnode-1.9.31-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"leafnode-1.9.31-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
