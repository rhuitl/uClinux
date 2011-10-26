# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-36.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16427);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200501-36");
 script_cve_id("CVE-2005-0116", "CVE-2005-0362", "CVE-2005-0363");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-36
(AWStats: Remote code execution)


    When \'awstats.pl\' is run as a CGI script, it fails to validate specific
    inputs which are used in a Perl open() function call. Furthermore, a
    user could read log file content even when plugin rawlog was not
    enabled.
  
Impact

    A remote attacker could supply AWStats malicious input, potentially
    allowing the execution of arbitrary code with the rights of the web
    server. He could also access raw log contents.
  
Workaround

    Making sure that AWStats does not run as a CGI script will avoid the
    issue, but we recommend that users upgrade to the latest version, which
    fixes these bugs.
  
References:
    http://awstats.sourceforge.net/docs/awstats_changelog.txt
    http://www.idefense.com/application/poi/display?id=185
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0116
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0362
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0363


Solution: 
    All AWStats users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-www/awstats-6.3-r2"
    Note: Users with the vhosts USE flag set should manually use
    webapp-config to finalize the update.
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-36] AWStats: Remote code execution");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'AWStats: Remote code execution');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-www/awstats", unaffected: make_list("ge 6.3-r2"), vulnerable: make_list("lt 6.3-r2")
)) { security_hole(0); exit(0); }
