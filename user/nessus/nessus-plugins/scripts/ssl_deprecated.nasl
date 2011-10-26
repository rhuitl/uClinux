#
# (C) Tenable Network Security
#


if (description) {
  script_id(20007);
  script_version("$Revision: 1.1 $");

  name["english"] = "Deprecated SSL Protocol Usage";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote service encrypts traffic using a protocol with known
weaknesses. 

Description :

The remote service accepts connections encrypted using SSL 2.0, which
reportedly suffers from several cryptographic flaws and has been
deprecated for several years.  An attacker may be able to exploit these
issues to conduct man-in-the-middle attacks or decrypt communications
between the affected service and clients. 

See also :

http://www.schneier.com/paper-ssl.pdf

Solution : 

Consult the application's documentation to disable SSL 2.0 and use SSL
3.0 or TLS 1.0 instead.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for use of a deprecated SSL protocol";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"General");
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("find_service.nes");

  exit(0);
}


port = get_kb_item("Transport/SSL");
if (!port) exit(0);
if (!get_port_state(port)) exit(0);


# There's a problem if we can connect using SSLv2.
soc = open_sock_tcp(port, transport:ENCAPS_SSLv2);
if (soc) {
  security_note(port);
  close(soc);
}
