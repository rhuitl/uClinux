# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-01.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16438);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200502-01");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200502-01
(FireHOL: Insecure temporary file creation)


    FireHOL insecurely creates temporary files with predictable names.
  
Impact

    A local attacker could create malicious symbolic links to
    arbitrary system files. When FireHOL is executed, this could lead to
    these files being overwritten with the rights of the user launching
    FireHOL, usually the root user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cvs.sourceforge.net/viewcvs.py/firehol/firehol/firehol.sh


Solution: 
    All FireHOL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-firewall/firehol-1.224"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200502-01] FireHOL: Insecure temporary file creation");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'FireHOL: Insecure temporary file creation');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-firewall/firehol", unaffected: make_list("ge 1.224"), vulnerable: make_list("lt 1.224")
)) { security_warning(0); exit(0); }
