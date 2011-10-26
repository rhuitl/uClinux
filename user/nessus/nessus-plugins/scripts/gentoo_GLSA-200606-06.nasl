# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-06.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21667);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200606-06");
 script_cve_id("CVE-2006-1945", "CVE-2006-2237");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200606-06
(AWStats: Remote execution of arbitrary code)


    Hendrik Weimer has found that if updating the statistics via the
    web frontend is enabled, it is possible to inject arbitrary code via a
    pipe character in the "migrate" parameter. Additionally, r0t has
    discovered that AWStats fails to properly sanitize user-supplied input
    in awstats.pl.
  
Impact

    A remote attacker can execute arbitrary code on the server in the
    context of the application running the AWStats CGI script if updating
    of the statistics via web frontend is allowed. Nonetheless, all
    configurations are affected by a cross-site scripting vulnerability in
    awstats.pl, allowing a remote attacker to execute arbitrary scripts
    running in the context of the victim\'s browser.
  
Workaround

    Disable statistics updates using the web frontend to avoid code
    injection. However, there is no known workaround at this time
    concerning the cross-site scripting vulnerability.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1945
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2237


Solution: 
    All AWStats users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-www/awstats-6.5-r1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200606-06] AWStats: Remote execution of arbitrary code");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'AWStats: Remote execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-www/awstats", unaffected: make_list("ge 6.5-r1"), vulnerable: make_list("lt 6.5-r1")
)) { security_hole(0); exit(0); }
