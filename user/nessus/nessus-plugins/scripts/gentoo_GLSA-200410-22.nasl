# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-22.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15558);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200410-22");
 script_cve_id("CVE-2004-0835", "CVE-2004-0836", "CVE-2004-0837");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200410-22
(MySQL: Multiple vulnerabilities)


    The following vulnerabilities were found and fixed in MySQL:
    Oleksandr Byelkin found that ALTER TABLE ... RENAME checks CREATE/INSERT
    rights of the old table instead of the new one (CVE-2004-0835). Another
    privilege checking bug allowed users to grant rights on a database they had
    no rights on.
    Dean Ellis found a defect where multiple threads ALTERing the MERGE tables
    to change the UNION could cause the server to crash (CVE-2004-0837).
    Another crash was found in MATCH ... AGAINST() queries with missing closing
    double quote.
    Finally, a buffer overrun in the mysql_real_connect function was found by
    Lukasz Wojtow (CVE-2004-0836).
  
Impact

    The privilege checking issues could be used by remote users to bypass their
    rights on databases. The two crashes issues could be exploited by a remote
    user to perform a Denial of Service attack on MySQL server. The buffer
    overrun issue could also be exploited as a Denial of Service attack, and
    may allow to execute arbitrary code with the rights of the MySQL daemon
    (typically, the "mysql" user).
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0835
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0836
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0837
    http://bugs.mysql.com/bug.php?id=3933
    http://bugs.mysql.com/bug.php?id=3870


Solution: 
    All MySQL users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=dev-db/mysql-4.0.21"
    # emerge ">=dev-db/mysql-4.0.21"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200410-22] MySQL: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MySQL: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-db/mysql", unaffected: make_list("ge 4.0.21"), vulnerable: make_list("lt 4.0.21")
)) { security_hole(0); exit(0); }
