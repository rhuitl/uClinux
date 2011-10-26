# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-16.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21709);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200606-16");
 script_cve_id("CVE-2006-2878");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200606-16
(DokuWiki: PHP code injection)


    Stefan Esser discovered that the DokuWiki spell checker fails to
    properly sanitize PHP\'s "complex curly syntax".
  
Impact

    A unauthenticated remote attacker may execute arbitrary PHP commands -
    and thus possibly arbitrary system commands - with the permissions of
    the user running the webserver that serves DokuWiki pages.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.hardened-php.net/advisory_042006.119.html
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2878


Solution: 
    All DokuWiki users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/dokuwiki-20060309-r1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200606-16] DokuWiki: PHP code injection");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'DokuWiki: PHP code injection');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/dokuwiki", unaffected: make_list("ge 20060309-r1"), vulnerable: make_list("lt 20060309-r1")
)) { security_hole(0); exit(0); }
