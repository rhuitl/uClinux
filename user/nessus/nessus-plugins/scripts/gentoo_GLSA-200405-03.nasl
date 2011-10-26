# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-03.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14489);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200405-03");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200405-03
(ClamAV VirusEvent parameter vulnerability)


    The VirusEvent parameter in the clamav.conf configuration file allows to
    specify a system command to run whenever a virus is found. This system
    command can make use of the "%f" parameter which is replaced by the name of
    the file infected. The name of the file scanned is under control of the
    attacker and is not sufficiently checked. Version 0.70 of clamav disables
    the use of the "%f" parameter.
  
Impact

    Sending a virus with a malicious file name can result in execution of
    arbirary system commands with the rights of the antivirus process. Since
    clamav is often associated to mail servers for email scanning, this attack
    can be used remotely.
  
Workaround

    You should not use the "%f" parameter in your VirusEvent configuration.
  
References:
    http://www.clamav.net/


Solution: 
    All users of Clam AntiVirus should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=net-mail/clamav-0.70"
    # emerge ">=net-mail/clamav-0.70"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200405-03] ClamAV VirusEvent parameter vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ClamAV VirusEvent parameter vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-mail/clamav", unaffected: make_list("ge 0.70"), vulnerable: make_list("lt 0.70")
)) { security_hole(0); exit(0); }
