# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-23.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16034);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200412-23");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200412-23
(Zwiki: XSS vulnerability)


    Due to improper input validation, Zwiki can be exploited to
    perform cross-site scripting attacks.
  
Impact

    By enticing a user to read a specially-crafted wiki entry, an
    attacker can execute arbitrary script code running in the context of
    the victim\'s browser.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://zwiki.org/925ZwikiXSSVulnerability


Solution: 
    All Zwiki users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-zope/zwiki-0.36.2-r1"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200412-23] Zwiki: XSS vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Zwiki: XSS vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-zope/zwiki", unaffected: make_list("ge 0.36.2-r1"), vulnerable: make_list("lt 0.36.2-r1")
)) { security_warning(0); exit(0); }
