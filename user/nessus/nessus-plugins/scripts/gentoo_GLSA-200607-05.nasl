# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200607-05.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22012);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200607-05");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200607-05
(SHOUTcast server: Multiple vulnerabilities)


    The SHOUTcast server is vulnerable to a file disclosure when the server
    receives a specially crafted GET request. Furthermore it also fails to
    sanitize the input passed to the "Description", "URL", "Genre", "AIM",
    and "ICQ" fields.
  
Impact

    By sending a specially crafted GET request to the SHOUTcast server, the
    attacker can read any file that can be read by the SHOUTcast process.
    Furthermore it is possible that various request variables could also be
    exploited to execute arbitrary scripts in the context of a victim\'s
    browser.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://people.ksp.sk/~goober/advisory/001-shoutcast.html
    http://secunia.com/advisories/20524/


Solution: 
    All SHOUTcast server users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-sound/shoutcast-server-bin-1.9.7"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200607-05] SHOUTcast server: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'SHOUTcast server: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-sound/shoutcast-server-bin", unaffected: make_list("ge 1.9.7"), vulnerable: make_list("lt 1.9.7")
)) { security_warning(0); exit(0); }
