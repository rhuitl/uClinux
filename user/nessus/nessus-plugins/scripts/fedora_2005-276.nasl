#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19643);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "Fedora Core 3 2005-276: squid";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-276 (squid).

Squid is a high-performance proxy caching server for Web clients,
supporting FTP, gopher, and HTTP data objects. Unlike traditional
caching software, Squid handles all requests in a single,
non-blocking, I/O-driven process. Squid keeps meta data and especially
hot objects cached in RAM, caches DNS lookups, supports non-blocking
DNS lookups, and implements negative caching of failed requests.

Squid consists of a main server program squid, a Domain Name System
lookup program (dnsserver), a program for retrieving FTP data
(ftpget), and some management and client tools.

Note that squid-2.5.STABLE7 and later do not use /etc/squid/errors for
error messages.  If you do not want to use the default English error
messages, you must set the error_directory in your
/etc/squid/squid.conf to the appropriate subdirectory of
/usr/share/squid/errors

* Wed Mar 23 2005 Jay Fenlason <fenlason redhat com> 7:2.5.STABLE9-1.FC3.4

- Add more upstream patches.
- add the -libbind patch, to avoid picking up a new dependency on libbind.
- Remove references to /etc/squid/errors from this spec, since squid
now uses {_datadir}/squid/errors/English/ by default (overridable in
/etc/squid/squid.conf, as always)
- mark {_datadir}/squid/errors as config(noreplace) so custom error messages
won't get stomped on.

* Wed Mar 16 2005 Jay Fenlason <fenlason redhat com> 7:2.5.STABLE9-1.FC3.3

- Actually apply the -date patch.

* Wed Mar 16 2005 Jay Fenlason <fenlason redhat com> 7:2.5.STABLE9-1.FC3.2

- New upstream version, with 14 patches.  Includes fix for
bz#150234 cookie leak in squid




Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the squid package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"squid-2.5.STABLE9-1.FC3.4", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
