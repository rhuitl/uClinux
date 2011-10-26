# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-26.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14582);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200408-26");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200408-26
(zlib: Denial of service vulnerability)


    zlib contains a bug in the handling of errors in the "inflate()"
    and "inflateBack()" functions.
  
Impact

    An attacker could exploit this vulnerability to launch a Denial of Service
    attack on any application using the zlib library.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of zlib.
  
References:
    http://www.openpkg.org/security/OpenPKG-SA-2004.038-zlib.html


Solution: 
    All zlib users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=sys-libs/zlib-1.2.1-r3"
    # emerge ">=sys-libs/zlib-1.2.1-r3"
    You should also run revdep-rebuild to rebuild any packages that depend on
    older versions of zlib :
    # revdep-rebuild
    Please note that any packages which have the zlib library compiled statically will not show up using revdep-rebuild.
    You will need to locate those packages manually and then remerge them.
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200408-26] zlib: Denial of service vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'zlib: Denial of service vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "sys-libs/zlib", unaffected: make_list("ge 1.2.1-r3"), vulnerable: make_list("le 1.2.1-r2")
)) { security_warning(0); exit(0); }
