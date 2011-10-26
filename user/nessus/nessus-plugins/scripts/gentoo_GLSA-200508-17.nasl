# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200508-17.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19537);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200508-17");
 script_cve_id("CVE-2005-2491");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200508-17
(libpcre: Heap integer overflow)


    libpcre fails to check certain quantifier values in regular
    expressions for sane values.
  
Impact

    An attacker could possibly exploit this vulnerability to execute
    arbitrary code by sending specially crafted regular expressions to
    applications making use of the libpcre library.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2491
    http://www.securitytracker.com/alerts/2005/Aug/1014744.html


Solution: 
    All libpcre users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-libs/libpcre-6.3"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200508-17] libpcre: Heap integer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libpcre: Heap integer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-libs/libpcre", unaffected: make_list("ge 6.3"), vulnerable: make_list("lt 6.3")
)) { security_hole(0); exit(0); }
