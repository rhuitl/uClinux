# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-33.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17236);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200502-33");
 script_cve_id("CVE-2005-0534", "CVE-2005-0535", "CVE-2005-0536");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200502-33
(MediaWiki: Multiple vulnerabilities)


    A security audit of the MediaWiki project discovered that
    MediaWiki is vulnerable to several cross-site scripting and cross-site
    request forgery attacks, and that the image deletion code does not
    sufficiently sanitize input parameters.
  
Impact

    By tricking a user to load a carefully crafted URL, a remote
    attacker could hijack sessions and authentication cookies to inject
    malicious script code that will be executed in a user\'s browser session
    in context of the vulnerable site, or use JavaScript submitted forms to
    perform restricted actions. Using the image deletion flaw, it is also
    possible for authenticated administrators to delete arbitrary files via
    directory traversal.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://secunia.com/advisories/14125/
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0534
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0535
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0536


Solution: 
    All MediaWiki users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/mediawiki-1.3.11"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200502-33] MediaWiki: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MediaWiki: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/mediawiki", unaffected: make_list("ge 1.3.11"), vulnerable: make_list("lt 1.3.11")
)) { security_warning(0); exit(0); }
