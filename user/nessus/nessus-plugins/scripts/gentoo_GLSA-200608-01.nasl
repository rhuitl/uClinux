# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-01.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22143);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200608-01");
 script_cve_id("CVE-2006-3747");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200608-01
(Apache: Off-by-one flaw in mod_rewrite)


    An off-by-one flaw has been found in Apache\'s mod_rewrite module by
    Mark Dowd of McAfee Avert Labs. This flaw is exploitable depending on
    the types of rewrite rules being used.
  
Impact

    A remote attacker could exploit the flaw to cause a Denial of Service
    or execution of arbitrary code. Note that Gentoo Linux is not
    vulnerable in the default configuration.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3747
    http://www.apache.org/dist/httpd/Announcement2.0.html
    http://www.apache.org/dist/httpd/Announcement1.3.html


Solution: 
    All Apache users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose net-www/apache
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200608-01] Apache: Off-by-one flaw in mod_rewrite");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache: Off-by-one flaw in mod_rewrite');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-www/apache", unaffected: make_list("rge 1.3.34-r14", "rge 1.3.37", "ge 2.0.58-r2"), vulnerable: make_list("lt 2.0.58-r2")
)) { security_hole(0); exit(0); }
