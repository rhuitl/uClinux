# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-18.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18382);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200505-18");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200505-18
(Net-SNMP: fixproc insecure temporary file creation)


    The fixproc application of Net-SNMP creates temporary files with
    predictable filenames.
  
Impact

    A malicious local attacker could exploit a race condition to
    change the content of the temporary files before they are executed by
    fixproc, possibly leading to the execution of arbitrary code. A local
    attacker could also create symbolic links in the temporary files
    directory, pointing to a valid file somewhere on the filesystem. When
    fixproc is executed, this would result in the file being overwritten.
  
Workaround

    There is no known workaround at this time.
  

Solution: 
    All Net-SNMP users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/net-snmp-5.2.1-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200505-18] Net-SNMP: fixproc insecure temporary file creation");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Net-SNMP: fixproc insecure temporary file creation');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-analyzer/net-snmp", unaffected: make_list("ge 5.2.1-r1"), vulnerable: make_list("lt 5.2.1-r1")
)) { security_warning(0); exit(0); }
