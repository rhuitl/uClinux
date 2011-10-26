# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-20.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14506);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200405-20");
 script_cve_id("CVE-2004-0381", "CVE-2004-0388");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200405-20
(Insecure Temporary File Creation In MySQL)


    The MySQL bug reporting utility (mysqlbug) creates a temporary file to log
    bug reports to. A malicious local user with write access to the /tmp
    directory could create a symbolic link of the name mysqlbug-N
    pointing to a protected file, such as /etc/passwd, such that when mysqlbug
    creates the Nth log file, it would end up overwriting the target
    file. A similar vulnerability exists with the mysql_multi utility, which
    creates a temporary file called mysql_multi.log.
  
Impact

    Since mysql_multi runs as root, a local attacker could use this to destroy
    any other users\' data or corrupt and destroy system files.
  
Workaround

    One could modify both scripts to log to a directory that users do not have
    write permission to, such as /var/log/mysql/.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0381
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0388


Solution: 
    All users should upgrade to the latest stable version of MySQL.
    # emerge sync
    # emerge -pv ">=dev-db/mysql-4.0.18-r2"
    # emerge ">=dev-db/mysql-4.0.18-r2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200405-20] Insecure Temporary File Creation In MySQL");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Insecure Temporary File Creation In MySQL');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-db/mysql", unaffected: make_list("ge 4.0.18-r2"), vulnerable: make_list("lt 4.0.18-r2")
)) { security_warning(0); exit(0); }
