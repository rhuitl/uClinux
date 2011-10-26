# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200508-02.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19364);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200508-02");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200508-02
(ProFTPD: Format string vulnerabilities)


     "infamous42md" reported that ProFTPD is vulnerable to format
    string vulnerabilities when displaying a shutdown message containing
    the name of the current directory, and when displaying response
    messages to the client using information retrieved from a database
    using mod_sql.
  
Impact

    A remote attacker could create a directory with a malicious name
    that would trigger the format string issue if specific variables are
    used in the shutdown message, potentially resulting in a Denial of
    Service or the execution of arbitrary code with the rights of the user
    running the ProFTPD server. An attacker with control over the database
    contents could achieve the same result by introducing malicious
    messages that would trigger the other format string issue when used in
    server responses.
  
Workaround

    Do not use the "%C", "%R", or "%U" in shutdown messages, and do
    not set the "SQLShowInfo" directive.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2390


Solution: 
    All ProFTPD users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-ftp/proftpd-1.2.10-r7"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200508-02] ProFTPD: Format string vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ProFTPD: Format string vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-ftp/proftpd", unaffected: make_list("ge 1.2.10-r7"), vulnerable: make_list("lt 1.2.10-r7")
)) { security_warning(0); exit(0); }
