# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-22.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19324);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200507-22");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200507-22
(sandbox: Insecure temporary file handling)


    The Gentoo Linux Security Audit Team discovered that the sandbox
    utility was vulnerable to multiple TOCTOU (Time of Check, Time of Use)
    file creation race conditions.
  
Impact

    Local users may be able to create or overwrite arbitrary files
    with the permissions of the root user.
  
Workaround

    There is no known workaround at this time.
  

Solution: 
    All sandbox users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-apps/sandbox-1.2.11"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200507-22] sandbox: Insecure temporary file handling");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'sandbox: Insecure temporary file handling');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "sys-apps/sandbox", unaffected: make_list("ge 1.2.11"), vulnerable: make_list("lt 1.2.11")
)) { security_warning(0); exit(0); }
