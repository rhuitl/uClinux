# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-31.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15587);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200410-31");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200410-31
(Archive::Zip: Virus detection evasion)


    Archive::Zip can be used by email scanning software (like amavisd-new) to
    uncompress attachments before virus scanning. By modifying the uncompressed
    size of archived files in the global header of the ZIP file, it is possible
    to fool Archive::Zip into thinking some files inside the archive have zero
    length.
  
Impact

    An attacker could send a carefully crafted ZIP archive containing a virus
    file and evade detection on some email virus-scanning software relying on
    Archive::Zip for decompression.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.idefense.com/application/poi/display?id=153
    http://rt.cpan.org/NoAuth/Bug.html?id=8077


Solution: 
    All Archive::Zip users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-perl/Archive-Zip-1.14"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200410-31] Archive::Zip: Virus detection evasion");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Archive::Zip: Virus detection evasion');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-perl/Archive-Zip", unaffected: make_list("ge 1.14"), vulnerable: make_list("lt 1.14")
)) { security_warning(0); exit(0); }
