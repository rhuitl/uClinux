# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200506-13.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18520);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200506-13");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200506-13
(webapp-config: Insecure temporary file handling)


    Eric Romang discovered webapp-config uses a predictable temporary
    filename while processing certain options, resulting in a race
    condition.
  
Impact

    Successful exploitation of the race condition would allow an
    attacker to disrupt the operation of webapp-config, or execute
    arbitrary shell commands with the privileges of the user running
    webapp-config. A local attacker could use a symlink attack to create or
    overwrite files with the permissions of the user running webapp-config.
  
Workaround

    There is no known workaround at this time.
  

Solution: 
    All webapp-config users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-www/webapp-config-1.11"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200506-13] webapp-config: Insecure temporary file handling");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'webapp-config: Insecure temporary file handling');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-www/webapp-config", unaffected: make_list("ge 1.11"), vulnerable: make_list("lt 1.11")
)) { security_warning(0); exit(0); }
