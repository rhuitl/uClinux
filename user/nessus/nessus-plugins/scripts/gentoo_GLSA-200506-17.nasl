# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200506-17.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18538);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200506-17");
 script_cve_id("CVE-2005-1266");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200506-17
(SpamAssassin 3, Vipul\'s Razor: Denial of Service vulnerability)


    SpamAssassin and Vipul\'s Razor contain a Denial of Service
    vulnerability when handling special misformatted long message headers.
  
Impact

    By sending a specially crafted message an attacker could cause a
    Denial of Service attack against the SpamAssassin/Vipul\'s Razor server.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1266
    http://mail-archives.apache.org/mod_mbox/spamassassin-announce/200506.mbox/%3c17072.35054.586017.822288@proton.pathname.com%3e
    http://sourceforge.net/mailarchive/forum.php?thread_id=7520323&forum_id=4259


Solution: 
    All SpamAssassin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-filter/spamassassin-3.0.4"
    All Vipul\'s Razor users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-filter/razor-2.71"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200506-17] SpamAssassin 3, Vipul's Razor: Denial of Service vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'SpamAssassin 3, Vipul\'s Razor: Denial of Service vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "mail-filter/spamassassin", unaffected: make_list("ge 3.0.4", "lt 3.0.1"), vulnerable: make_list("lt 3.0.4")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "mail-filter/razor", unaffected: make_list("ge 2.71"), vulnerable: make_list("lt 2.71")
)) { security_warning(0); exit(0); }
