#
# (C) Tenable Network Security
#

desc = "
Synopsis :

The remote router allows anonymous users to retrieve the administrative password

Description :

The remote host appears to be running a Netopia router with SNMP enabled.
Further, the Netopia router is using the default SNMP community strings.
This version of the Netopia firmware is vulnerable to a flaw wherein
a remote attacker can, by sending a specially formed SNMP query, retrieve
the Administrative password.

An attacker, exploiting this flaw, would only need to be able to send SNMP
queries to the router using the default community string of 'public'.
Successful exploitation would result in the attacker gaining administrative
credentials to the router.

See also :

http://www.netopia.com/

Solution :

Contact the vendor for a patch.  Change the default SNMP community string to
one that is not easily guessed.

Risk factor :

High / CVSS Base Score : 10
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";


if (description)
{
 script_id(22415);
 script_version("$Revision: 1.1 $");

 script_name(english:"Netopia SNMP password disclosure flaw");
 script_summary(english:"Checks to see if the router will disclose the admin password");
 script_description(english:desc);

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

 script_dependencie("snmp_settings.nasl");
 script_require_keys("SNMP/community");
 exit(0);
}


include ("snmp_func.inc");

community = get_kb_item("SNMP/community");
if(!community)exit(0);

port = get_kb_item("SNMP/port");
if(!port)port = 161;

soc = open_sock_udp(port);
if (!soc)
  exit (0);

password = snmp_request (socket:soc, community:community, oid:"1.3.6.1.4.1.304.1.3.1.23.1.0");

if(strlen(password))
{
 report = string (desc,
		"\n\nPlugin output :\n\n",
		"The administrator password is '", password, "'.");

 security_hole(port:port, data:report, protocol:"udp");
}
