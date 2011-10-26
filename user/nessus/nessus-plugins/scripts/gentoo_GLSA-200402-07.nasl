# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200402-07.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14451);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200402-07");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200402-07
(Clam Antivirus DoS vulnerability)


    Oliver Eikemeier of Fillmore Labs discovered the overflow in Clam AV 0.65
    when it handled malformed UUEncoded messages, causing the daemon to shut
    down.
    The problem originated in libclamav which calculates the line length of an
    uuencoded message by taking the ASCII value of the first character minus 64
    while doing an assertion if the length is not in the allowed range,
    effectively terminating the calling program as clamav would not be
    available.
  
Impact

    A malformed message such as the one below would cause a denial of service,
    and depending on the server configuration this may impact other daemons
    relying on Clam AV in a fatal manner.
    To exploit the vulnerability, you can add the following to ~/clamtest.mbox:
    From -
    begin 644 byebye
    byebye
    end
    Then do "clamscan --mbox -v ~/clamtest.mbox" or "clamdscan
    -v ~/clamtest.mbox; ps ax | grep clam": the former will cause an
    assertion and a segmentation fault, the latter would cause the daemon to
    shut down.
  
Workaround

    There is no immediate workaround, a software upgrade is required.
  

Solution: 
    All users are urged to upgrade their Clam AV installations to Clam AV 0.67:
    # emerge sync
    # emerge -pv ">=net-mail/clamav-0.6.7"
    # emerge ">=net-mail/clamav-0.6.7"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200402-07] Clam Antivirus DoS vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Clam Antivirus DoS vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-mail/clamav", unaffected: make_list("ge 0.67"), vulnerable: make_list("lt 0.67")
)) { security_warning(0); exit(0); }
