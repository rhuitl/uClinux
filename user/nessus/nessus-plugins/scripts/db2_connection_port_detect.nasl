#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote host has an open connection port for a DB2 instance. 

Description :

The remote host is running DB2, with an open connection port for a DB2
instance.  DB2 is a commercial database from IBM, and a connection
port is used by remote clients when connecting to a DB2 server
instance. 

See also :

http://www.ibm.com/software/data/db2/
http://www.nessus.org/u?3c362c6e

Solution :

Limit incoming traffic to this port if desired.

Risk factor :

None";


if (description)
{
  script_id(22416);
  script_version("$Revision: 1.1 $");

  script_name(english:"DB2 Connection Port Detection");
  script_summary(english:"Detects a DB2 Connection Port");

  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 50000);

  exit(0);
}


include("byte_func.inc");
include("charset_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests) {
  port = get_unknown_svc(50000);
  if (!port) exit(0);
}
else port = 50000;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Try to connect to a database named "nessus" + unixtime().
req = 
  mkword(0x89) +                       # length (?)
    mkbyte(0xd0) +                     #   type (?)
    raw_string(0x41, 0x00, 0x01, 0x00, 0x83, 0x10, 0x41) +     # ?
    mkword(0x39) +                     #   length (?)
      mkbyte(0x11) +                   #     type, 0x11 => string (?)
      ascii2ebcdic(
        str:";db2jcc_application  JCC020800.GA0A01CB" + 
          raw_string(
            0x2e, 0x01, 0x0c, 0xe1, 0xe9, 0x3e, 0x9d, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
          )
      ) +
    mkword(0x16) +                     #   length (?)
      mkbyte(0x11) +                   #     type, 0x11 => string (?)
      ascii2ebcdic(str:"_nessus" + unixtime() + "  ") +
    mkword(0x0c) +                     #   length (?)
      mkbyte(0x11) +                   #     type, 0x11 => string (?)
      ascii2ebcdic(str:"!JCC02080") +
    mkword(0x18) +                     #   length (?)
      mkbyte(0x14) +                   #     type (?)
      raw_string(
        0x04, 0x14, 0x03, 0x00, 0x07, 0x24, 0x07, 0x00, 
        0x07, 0x24, 0x0f, 0x00, 0x07, 0x14, 0x40, 0x00, 
        0x07, 0x14, 0x74, 0x00, 0x05
      ) +
    mkword(0x0c) +                     #   length (?)
      mkbyte(0x11) +                   #     type, 0x11 => string (?)
      ascii2ebcdic(str:raw_string(0xe5) + "QDB2/JVM") +
  mkword(0x26) +                       # length (?)
    mkbyte(0xd0) +                     #   type (?)
    raw_string(
      0x01, 0x00, 0x02, 0x00, 0x20, 0x10, 0x6d, 0x00, 
      0x06, 0x11, 0xa2, 0x00, 0x03, 0x00, 0x16, 0x21, 
      0x10, 0xe2, 0xc1, 0xd4, 0xd7, 0xd3, 0xc5, 0x40, 
      0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 
      0x40, 0x40, 0x40
    );
send(socket:soc, data:req);
res = recv(socket:soc, length:2048);
close(soc);


# If first record is of type 0xd0...
if (strlen(res) > 3 && getbyte(blob:res, pos:2) == 0xd0)
{
  # Extract it.
  len = getword(blob:res, pos:0);
  if (len > 0 && len <= strlen(res))
  {
    rec = substr(res, 0, len-1);

    # If it looks like a DB2 instance connection port...
    if (
      ascii2ebcdic(str:"QDB2/") >< rec &&
      ascii2ebcdic(str:"DB2CTLSV") >!< rec
    )
    {
      # Grab the application info.
      app = "";
      i = stridx(res, ascii2ebcdic(str:"QDB2/"));
      if (i > 0 && getbyte(blob:res, pos:i-2) == 0x11)
      {
        len = getword(blob:res, pos:i-4);
        if (len > 0) app = ebcdic2ascii(str:substr(res, i+1, i+len-4-1));

        j = stridx(res, ascii2ebcdic(str:"!SQL"));
        if (j > 0 && getbyte(blob:res, pos:j-1) == 0x11)
        {
          len = getword(blob:res, pos:j-3);
          if (len > 0)
          {
            ver = ebcdic2ascii(str:substr(res, j+4, j+len-3-1));
            app += " " + 
              int(substr(ver, 0, 1)) + "." +
              int(substr(ver, 2, 3)) + "." +
              int(substr(ver, 4, 4));
          }
        }
      }

      # Register and report the service.
      register_service(port:port, ipproto:"tcp", proto:"db2c_db2");

      if (report_verbosity && app) 
        report = string(
          desc,
          "\n\n",
          "Plugin output :\n",
          "\n",
          "Application : ", app, "\n"
        );
      else report = desc;
      security_note(port:port, data:report);
    }
  }
}
