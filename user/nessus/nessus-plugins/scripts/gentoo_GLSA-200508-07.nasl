# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200508-07.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19440);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200508-07");
 script_cve_id("CVE-2005-1527");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200508-07
(AWStats: Arbitrary code execution using malicious Referrer information)


    When using a URLPlugin, AWStats fails to sanitize Referrer URL
    data before using them in a Perl eval() routine.
  
Impact

    A remote attacker can include arbitrary Referrer information in a
    HTTP request to a web server, therefore injecting tainted data in the
    log files. When AWStats is run on this log file, this can result in the
    execution of arbitrary Perl code with the rights of the user running
    AWStats.
  
Workaround

    Disable all URLPlugins in the AWStats configuration.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1527
    http://www.idefense.com/application/poi/display?id=290&type=vulnerabilities


Solution: 
    All AWStats users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-www/awstats-6.5"
    Note: Users with the vhosts USE flag set should manually use
    webapp-config to finalize the update.
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200508-07] AWStats: Arbitrary code execution using malicious Referrer information");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'AWStats: Arbitrary code execution using malicious Referrer information');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-www/awstats", unaffected: make_list("ge 6.5"), vulnerable: make_list("lt 6.5")
)) { security_hole(0); exit(0); }
