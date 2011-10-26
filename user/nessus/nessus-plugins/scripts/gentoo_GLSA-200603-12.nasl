# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-12.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21085);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200603-12");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200603-12
(zoo: Buffer overflow)


    zoo is vulnerable to a new buffer overflow due to insecure use of
    the strcpy() function when trying to create an archive from certain
    directories or filenames.
  
Impact

    An attacker could exploit this issue by enticing a user to create
    a zoo archive of specially crafted directories and filenames, possibly
    leading to the execution of arbitrary code with the rights of the user
    running zoo.
  
Workaround

    There is no known workaround at this time.
  
References:
    https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=183426


Solution: 
    All zoo users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-arch/zoo-2.10-r2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200603-12] zoo: Buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'zoo: Buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-arch/zoo", unaffected: make_list("ge 2.10-r2"), vulnerable: make_list("lt 2.10-r2")
)) { security_warning(0); exit(0); }
