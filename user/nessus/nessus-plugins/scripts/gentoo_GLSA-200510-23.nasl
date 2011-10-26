# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200510-23.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20116);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200510-23");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200510-23
(TikiWiki: XSS vulnerability)


    Due to improper input validation, TikiWiki can be exploited to
    perform cross-site scripting attacks.
  
Impact

    A remote attacker could exploit this to inject and execute
    malicious script code or to steal cookie-based authentication
    credentials, potentially compromising the victim\'s browser.
  
Workaround

    There is no known workaround at this time.
  

Solution: 
    All TikiWiki users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/tikiwiki-1.9.1.1"
    Note: Users with the vhosts USE flag set should manually use
    webapp-config to finalize the update.
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200510-23] TikiWiki: XSS vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'TikiWiki: XSS vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/tikiwiki", unaffected: make_list("ge 1.9.1.1"), vulnerable: make_list("lt 1.9.1.1")
)) { security_warning(0); exit(0); }
