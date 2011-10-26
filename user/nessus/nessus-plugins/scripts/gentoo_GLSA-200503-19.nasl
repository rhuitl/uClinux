# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-19.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17344);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200503-19");
 script_cve_id("CVE-2005-0709", "CVE-2005-0710", "CVE-2005-0711");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200503-19
(MySQL: Multiple vulnerabilities)


    MySQL fails to properly validate input for authenticated users with
    INSERT and DELETE privileges (CVE-2005-0709 and CVE-2005-0710).
    Furthermore MySQL uses predictable filenames when creating temporary
    files with CREATE TEMPORARY TABLE (CVE-2005-0711).
  
Impact

    An attacker with INSERT and DELETE privileges could exploit this to
    manipulate the mysql table or accessing libc calls, potentially leading
    to the execution of arbitrary code with the permissions of the user
    running MySQL. An attacker with CREATE TEMPORARY TABLE privileges could
    exploit this to overwrite arbitrary files via a symlink attack.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0709
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0710
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0711


Solution: 
    All MySQL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-db/mysql-4.0.24"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200503-19] MySQL: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MySQL: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-db/mysql", unaffected: make_list("ge 4.0.24"), vulnerable: make_list("lt 4.0.24")
)) { security_warning(0); exit(0); }
