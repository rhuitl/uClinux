#
# (C) Tenable Network Security
#
#
# Thanks to the following persons for having sent additional
# SNMP communities over time :
#
# Javier Fernandez-Sanguino, Axel Nennker and the following references :
#
# From: Raphael Muzzio (rmuzzio_at_ZDNETMAIL.COM)
# Date: Nov 15 1998 
# To: bugtraq@securityfocus.com
# Subject:  Re: ISS Security Advisory: Hidden community string in SNMP
# (http://lists.insecure.org/lists/bugtraq/1998/Nov/0212.html)
# 
# Date: Mon, 5 Aug 2002 19:01:24 +0200 (CEST)
# From:"Jacek Lipkowski" <sq5bpf@andra.com.pl>
# To: bugtraq@securityfocus.com
# Subject: SNMP vulnerability in AVAYA Cajun firmware 
# Message-ID: <Pine.LNX.4.44.0208051851050.3610-100000@hash.intra.andra.com.pl>
#
# From:"Foundstone Labs" <labs@foundstone.com>
# To: da@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: Foundstone Labs Advisory - Information Leakage in Orinoco and Compaq Access Points
# Message-ID: <9DC8A3D37E31E043BD516142594BDDFAC476B0@MISSION.foundstone.com>
#
# CC:da@securityfocus.com, vulnwatch@vulnwatch.org
# To:"Foundstone Labs" <labs@foundstone.com>
# From:"Rob Flickenger" <rob@oreillynet.com>
# In-Reply-To: <9DC8A3D37E31E043BD516142594BDDFAC476B0@MISSION.foundstone.com>
# Message-Id: <D8F6A4EC-ABE3-11D6-AF54-0003936D6AE0@oreillynet.com>
# Subject: Re: [VulnWatch] Foundstone Labs Advisory - Information Leakage in Orinoco and Compaq Access Points
# 
# http://www.securityfocus.com/archive/1/313714/2003-03-01/2003-03-07/0
# http://www.iss.net/issEn/delivery/xforce/alertdetail.jsp?id=advise15 
#

 desc["english"] = "
Synopsis :

The community name of the remote SNMP server can be guessed.

Description :

It is possible to obtain the default community names of the remote
SNMP server.

An attacker may use this information to gain more knowledge about
the remote host, or to change the configuration of the remote
system (if the default community allow such modifications).

Solution : 

Disable the SNMP service on the remote host if you do not use it,
filter incoming UDP packets going to this port, or change the 
default community string.

Risk factor : 

High";

if(description)
{
 script_id(10264);
 script_version ("$Revision: 1.74 $");
 script_bugtraq_id(11237, 10576, 177, 2112, 6825, 7081, 7212, 7317, 9681, 986);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2001-B-0001");
 script_cve_id("CVE-1999-0517", "CVE-1999-0186", "CVE-1999-0254", "CVE-1999-0516");
 
 name["english"] = "Default community names of the SNMP Agent";
 script_name(english:name["english"]);

 script_description(english:desc["english"]);
 
 summary["english"] = "Default community names of the SNMP Agent";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "SNMP";
 script_family(english:family["english"]);
 
 exit(0);
}

include ("snmp_func.inc");

port = get_kb_item("SNMP/port");
if(!port)port = 161;



default = make_list ( "private", "public", "cisco");

extra = make_list (
	"monitor", "agent", "manager", "OrigEquipMfr", "default", "tivoli",
	"openview", "community", "snmp", "snmpd", "Secret C0de", "security",
	"rmon", "rmon_admin", "hp_admin", "NoGaH$@!", "0392a0", "xyzzy",
	"agent_steal", "freekevin", "fubar", "apc", "ANYCOM", "cable-docsis",
	"c", "cc", "Cisco router", "cascade", "comcomcom", "internal", "blue",
	"yellow", "TENmanUFactOryPOWER", "regional", "core", get_host_name(), "secret", 
	"write", "test", "guest", "ilmi", "ILMI", "system", "all", "admin", 
	"all private", "password", "default", "riverhead", "proxy"
	);

comm_list = NULL;
comm_number = 0;

if (thorough_test)
{
 default = make_list (default, extra);
}

foreach community (default)
{
 soc = open_sock_udp(port);
 if (!soc) exit (0); # Hu ?
 rep = snmp_request_next (socket:soc, community:community, oid:"1.3", timeout:3);
 if (!isnull(rep))
 {
  # Sun ...
  if ((rep[1] != "/var/snmp/snmpdx.st") && (rep[1] != "/etc/snmp/conf"))
  {
   comm_list = string (comm_list, community, "\n");
   comm_number++;
  }
 }
 close(soc);
}


if (strlen(comm_list))
{
 if (comm_number > 5)
   comm_list = string (
		"The remote SNMP server replies to all default community strings.\n",
		"This may be due to a badly configured server or due to some printer's\n",
		"SNMP server."
		);
 else
   comm_list = string (
		"The remote SNMP server replies to the following default community\n",
		"strings :\n\n",
		comm_list
		); 

 report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		comm_list);

 security_hole(port:port, data:report, protocol:"udp");
}
