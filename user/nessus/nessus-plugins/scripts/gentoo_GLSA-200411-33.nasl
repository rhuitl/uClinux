# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-33.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15827);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200411-33");
 script_cve_id("CVE-2004-1037");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200411-33
(TWiki: Arbitrary command execution)


    The TWiki search function, which uses a shell command executed via
    the Perl backtick operator, does not properly escape shell
    metacharacters in the user-provided search string.
  
Impact

    An attacker can insert malicious commands into a search request,
    allowing the execution of arbitrary commands with the privileges of the
    user running TWiki (usually the Web server user).
  
Workaround

    There is no known workaround at this time.
  
References:
    http://twiki.org/cgi-bin/view/Codev/SecurityAlertExecuteCommandsWithSearch
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1037


Solution: 
    All TWiki users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/twiki-20040902"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200411-33] TWiki: Arbitrary command execution");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'TWiki: Arbitrary command execution');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/twiki", unaffected: make_list("ge 20040902 "), vulnerable: make_list("lt 20040902 ")
)) { security_hole(0); exit(0); }
