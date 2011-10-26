#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#



if(description)
{
  script_id(11123);
  script_version ("$Revision: 1.8 $");
 
  script_name(english:"radmin detection");
 
  desc["english"] = "
radmin is running on this port. 
Make sure that you use a strong password, otherwise a cracker
may brute-force it and control your machine.

If you did not install this on the computer, you may have
been hacked into.
See: http://www.secnap.com/security/radmin001.html

Solution: disable it if you do not use it

Risk factor : Medium";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect radmin";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
  family["english"] = "Backdoors";
  script_family(english:family["english"]);
  script_dependencie("find_service2.nasl");
  script_require_ports("Services/unknown", 4899);

  exit(0);
}

include ("misc_func.inc");


if(safe_checks())
{
 port = 4899;
}
else
{
 port = get_unknown_svc(4899);
 if ( ! port ) exit(0);
}
if (! get_port_state(port)) exit(0);

if (! service_is_unknown(port: port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

req = raw_string(0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x08);
send(socket: soc, data: req);
#r = recv(socket: soc, length: 16);
r = recv(socket: soc, length: 6);
close(soc);

# I got :
# 0000000 001  \0  \0  \0   %  \0  \0 001 020  \b 001  \0  \0  \b  \0  \0
#         01 00 00 00 25 00 00 01 10 08 01 00 00 08 00 00
# 0000020  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0
#         00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
# 0000040  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0  \0
#         00 00 00 00 00 00 00 00 00 00 00 00 00 00
# 0000056
#
# Noam Rathaus <noamr@beyondsecurity.com> saw differents replies,
# depending on the security settings:
#  password security => 6th byte (r[5]) == 0
#  NTLM security     => 6th byte (r[5]) == 1
# I tried, and always got the same answer, whatever the security setting is.
# Odd...
# 

#xp = raw_string(0x01, 0x00, 0x00, 0x00, 0x25, 0x00, 0x00, 0x01, 
#                0x10, 0x08, 0x01, 0x00, 0x00, 0x08, 0x00, 0x00);

xp1 = "010000002500";
xp2 = "010000002501";



if (( xp1 >< hexstr(r) ) || ( xp2 >< hexstr(r) ))
{
        security_warning(port);
        register_service(port: port, proto: "radmin");
	exit(0);
}


