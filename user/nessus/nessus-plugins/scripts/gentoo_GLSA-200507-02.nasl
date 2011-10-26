# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-02.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18606);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200507-02");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200507-02
(WordPress: Multiple vulnerabilities)


    James Bercegay of the GulfTech Security Research Team discovered
    that WordPress insufficiently checks data passed to the XML-RPC server.
    He also discovered that WordPress has several cross-site scripting and
    full path disclosure vulnerabilities.
  
Impact

    An attacker could use the PHP script injection vulnerabilities to
    execute arbitrary PHP script commands. Furthermore the cross-site
    scripting vulnerabilities could be exploited to execute arbitrary
    script code in a user\'s browser session in context of a vulnerable
    site.
  
Workaround

    There are no known workarounds at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1921
    http://www.gulftech.org/?node=research&article_id=00085-06282005


Solution: 
    All WordPress users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/wordpress-1.5.1.3"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200507-02] WordPress: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'WordPress: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/wordpress", unaffected: make_list("ge 1.5.1.3"), vulnerable: make_list("lt 1.5.1.3")
)) { security_hole(0); exit(0); }
