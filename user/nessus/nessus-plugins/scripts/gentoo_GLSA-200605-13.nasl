# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200605-13.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21355);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200605-13");
 script_cve_id("CVE-2006-1516", "CVE-2006-1517");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200605-13
(MySQL: Information leakage)


    The processing of the COM_TABLE_DUMP command by a MySQL server
    fails to properly validate packets that arrive from the client via a
    network socket.
  
Impact

    By crafting specific malicious packets an attacker could gather
    confidential information from the memory of a MySQL server process, for
    example results of queries by other users or applications. By using PHP
    code injection or similar techniques it would be possible to exploit
    this flaw through web applications that use MySQL as a database
    backend.
    Note that on 5.x versions it is possible to overwrite
    the stack and execute arbitrary code with this technique. Users of
    MySQL 5.x are urged to upgrade to the latest available version.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.derkeiler.com/Mailing-Lists/securityfocus/bugtraq/2006-05/msg00041.html
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1516
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1517


Solution: 
    All MySQL users should upgrade to the latest version.
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-db/mysql-4.1.19"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200605-13] MySQL: Information leakage");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MySQL: Information leakage');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-db/mysql", unaffected: make_list("ge 4.1.19"), vulnerable: make_list("lt 4.1.19")
)) { security_warning(0); exit(0); }
