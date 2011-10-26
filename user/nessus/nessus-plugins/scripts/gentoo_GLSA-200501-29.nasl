# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-29.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16420);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200501-29");
 script_cve_id("CVE-2004-1177");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-29
(Mailman: Cross-site scripting vulnerability)


    Florian Weimer has discovered a cross-site scripting vulnerability
    in the error messages that are produced by Mailman.
  
Impact

    By enticing a user to visiting a specially-crafted URL, an
    attacker can execute arbitrary script code running in the context of
    the victim\'s browser.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1177


Solution: 
    All Mailman users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/mailman-2.1.5-r3"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-29] Mailman: Cross-site scripting vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mailman: Cross-site scripting vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-mail/mailman", unaffected: make_list("ge 2.1.5-r3"), vulnerable: make_list("lt 2.1.5-r3")
)) { security_warning(0); exit(0); }
