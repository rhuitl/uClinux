# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200512-10.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20330);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200512-10");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200512-10
(Opera: Command-line URL shell command injection)


    Peter Zelezny discovered that the shell script used to launch
    Opera parses shell commands that are enclosed within backticks in the
    URL provided via the command line.
  
Impact

    A remote attacker could exploit this vulnerability by enticing a
    user to follow a specially crafted URL from a tool that uses Opera to
    open URLs, resulting in the execution of arbitrary commands on the
    targeted machine.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3750
    http://www.opera.com/docs/changelogs/linux/851/


Solution: 
    All Opera users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/opera-8.51"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200512-10] Opera: Command-line URL shell command injection");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Opera: Command-line URL shell command injection');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-client/opera", unaffected: make_list("ge 8.51"), vulnerable: make_list("lt 8.51")
)) { security_warning(0); exit(0); }
