# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-16.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15513);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200410-16");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200410-16
(PostgreSQL: Insecure temporary file use in make_oidjoins_check)


    The make_oidjoins_check script insecurely creates temporary files in
    world-writeable directories with predictable names.
  
Impact

    A local attacker could create symbolic links in the temporary files
    directory, pointing to a valid file somewhere on the filesystem. When
    make_oidjoins_check is called, this would result in file overwrite with the
    rights of the user running the utility, which could be the root user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.trustix.org/errata/2004/0050/


Solution: 
    All PostgreSQL users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=dev-db/postgresql-7.4.5-r2"
    # emerge ">=dev-db/postgresql-7.4.5-r2"
    Upgrade notes: PostgreSQL 7.3.x users should upgrade to the latest
    available 7.3.x version to retain database compatibility.
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200410-16] PostgreSQL: Insecure temporary file use in make_oidjoins_check");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PostgreSQL: Insecure temporary file use in make_oidjoins_check');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-db/postgresql", unaffected: make_list("ge 7.4.5-r2", "rge 7.3.7-r2"), vulnerable: make_list("le 7.4.5-r1")
)) { security_warning(0); exit(0); }
