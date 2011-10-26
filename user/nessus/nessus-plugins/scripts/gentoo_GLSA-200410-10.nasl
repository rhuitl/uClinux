# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-10.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15448);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200410-10");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200410-10
(gettext: Insecure temporary file handling)


    gettext insecurely creates temporary files in world-writeable
    directories with predictable names.
  
Impact

    A local attacker could create symbolic links in the temporary files
    directory, pointing to a valid file somewhere on the filesystem. When
    gettext is called, this would result in file access with the rights of
    the user running the utility, which could be the root user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.securityfocus.com/advisories/7263


Solution: 
    All gettext users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-devel/gettext-0.14.1-r1"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200410-10] gettext: Insecure temporary file handling");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'gettext: Insecure temporary file handling');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "sys-devel/gettext", unaffected: make_list("ge 0.14.1-r1", "rge 0.12.1-r2"), vulnerable: make_list("lt 0.14.1-r1")
)) { security_warning(0); exit(0); }
