# -*- Fundamental -*-
#
# 
# (C) 2006 Tenable Network Security
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# See the following licenses for details :
#  http://www.nessus.org/plugins/RegisteredFeed.pdf
#  http://www.nessus.org/plugins/TenableCommercial.pdf
#  http://www.nessus.org/plugins/DirectFeed.pdf
#  http://www.nessus.org/plugins/DirectFeedCommercial.pdf
#
#
# @NOGPL@
#
# mysql_func.inc
# $Revision: 1.1 $
#


include("byte_func.inc");


# For information on the MySQL Client/Server protocol, see:
#     http://dev.mysql.com/doc/internals/en/client-server-protocol.html and
#     http://www.redferni.uklinux.net/mysql/MySQL-Protocol.html
global_var _mysql;


set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);


function mysql_open(soc)
{
  local_var hip, l;

  if (isnull(soc))
  {
    display("mysql_open: 'soc' argument missing.\n");
    return -1;
  }
  _mysql["soc"] = soc;

  hip = mysql_recv_packet();
  if (isnull(hip))
  {
    mysql_close();
    return -1;
  }

  if (mysql_is_error_packet(packet:hip))
  {
    _mysql["err"] = hip;
    return 0;
  }
  else _mysql["err"] = NULL;

  _mysql["proto"]     = getbyte(blob:hip["data"], pos:0);
  _mysql["ver"]       = mysql_get_null_string(blob:hip["data"], pos:1);
  l = strlen(_mysql["ver"]);
  _mysql["thread_id"] = getdword(blob:hip["data"], pos:2+l);
  _mysql["salt"]      = substr(hip["data"], 6+l, 13+l);
  _mysql["caps"]      = getword(blob:hip["data"], pos:15+l);
  _mysql["lang"]      = getbyte(blob:hip["data"], pos:17+l);
  _mysql["status"]    = getword(blob:hip["data"], pos:18+l);
  # nb: I didn't find this addition to the salt documented on mysql.com, 
  #     but Net::MySQL uses it.
  if ((_mysql["caps"] & 512) && strlen(hip["data"]) > 44+l)
    _mysql["salt2"] = substr(hip["data"], 33+l, 44+l);
  return 1;
}


function mysql_close()
{
  if (!isnull(_mysql) && !isnull(_mysql["soc"])) close(_mysql["soc"]);
  _mysql = NULL;
}


function mysql_recv_packet()
{
  local_var hdr, pkt, soc;

  if (isnull(_mysql))
  {
    display("mysql_recv_packet: need to call mysql_open first.\n");
    return NULL;
  }
  soc = mysql_get_socket();

  # Read the packet header.
  hdr = recv(socket:soc, length:4);
  if (strlen(hdr) != 4) return NULL;

  pkt["len"] = ord(hdr[0]) + (ord(hdr[1]) << 8) + (ord(hdr[2]) << 16);
  pkt["num"] = ord(hdr[3]);

  # And now the packet.
  pkt["data"] = recv(socket:soc, length:pkt["len"]);
  if (strlen(pkt["data"]) != pkt["len"]) return NULL;

  return pkt;
}


function mysql_send_packet(data, len, num)
{
  if (isnull(data))
  {
    display("mysql_send_packet: 'data' argument missing.\n");
    return NULL;
  }

  if (isnull(len)) len = strlen(data);
  if (isnull(num)) num = 1;
  send(
    socket : mysql_get_socket(), 
    data   : raw_string(len & 0xff, (len >> 8) & 0xff, (len >> 16) & 0xff) +
             mkbyte(num) +
             data
  );
  return strlen(data) + 4;
}


function mysql_login(user, pass, db, flags, max_pkt_sz, charset)
{
  local_var cap, pkt, scramble;

  if (isnull(_mysql))
  {
    display("mysql_login: need to call mysql_open first.\n");
    return NULL;
  }
  if (isnull(user))
  {
    display("mysql_login: 'user' argument missing.\n");
    return NULL;
  }

  if (isnull(flags)) flags = mysql_get_caps();
  if (isnull(max_pkt_sz)) max_pkt_sz = 0xFFFF;
  if (isnull(charset)) charset = mysql_get_lang();

  cap = 
    mkdword(flags) +                       # client capabilities
    mkdword(max_pkt_sz) +                  # max packet size
    mkbyte(charset) +                      # charset
    crap(data:raw_string(0), length:23) +  # filler
    user + mkbyte(0);
  if (strlen(pass))
  {
    # TO DO.
    #
    # nb: this works for the 4.1 protocol, but only if the server doesn't
    # fallback to the older scheme.
    if (mysql_is_proto41_supported())
      scramble = mysql_get_scramble(pass:pass, msg:mysql_get_salt());
    else
      scramble = mysql_get_scramble323(pass:pass, msg:mysql_get_salt(), proto:10);
    if (strlen(scramble))
      cap += mkbyte(strlen(scramble)) + scramble;
  }
  if (strlen(db))
    cap += db + mkbyte(0);

  mysql_send_packet(data:cap, len:strlen(cap));
  pkt = mysql_recv_packet();

  # Handle case of a 4.1 server with an older password table.
  if (pkt && (pkt["data"] == raw_string(0xfe)))
  {
    # NB: untested.
    scramble = mysql_get_scramble323(pass:pass, msg:mysql_get_salt(), proto:10) + 
      mkbyte(0);
    mysql_send_packet(data:scramble, num:res["num"]+1);
    pkt = mysql_recv_packet();
  }


  if (mysql_is_error_packet(packet:pkt))
  {
    _mysql["err"] = pkt;
    return 0;
  }
  else return 1;
}


function mysql_get_socket()
{
  if (isnull(_mysql))
  {
    display("mysql_get_socket: need to call mysql_open first.\n");
    return NULL;
  }
  return _mysql["soc"];
}


function mysql_get_protocol()
{
  if (isnull(_mysql))
  {
    display("mysql_get_protocol: need to call mysql_open first.\n");
    return NULL;
  }
  return _mysql["proto"];
}


function mysql_get_version()
{
  if (isnull(_mysql))
  {
    display("mysql_get_version: need to call mysql_open first.\n");
    return NULL;
  }
  return _mysql["ver"];
}


function mysql_get_thread_id()
{
  if (isnull(_mysql))
  {
    display("mysql_get_thread_id: need to call mysql_open first.\n");
    return NULL;
  }
  return _mysql["thread_id"];
}


function mysql_get_salt(bits)
{
  if (isnull(_mysql))
  {
    display("mysql_get_salt: need to call mysql_open first.\n");
    return NULL;
  }
  if (mysql_is_proto41_supported() && (isnull(bits) || bits == 20)) 
    return string(_mysql["salt"], _mysql["salt2"]);
  else 
    return _mysql["salt"];
}


function mysql_get_caps()
{
  if (isnull(_mysql))
  {
    display("mysql_get_caps: need to call mysql_open first.\n");
    return NULL;
  }
  return _mysql["caps"];
}


function mysql_get_lang()
{
  if (isnull(_mysql))
  {
    display("mysql_get_lang: need to call mysql_open first.\n");
    return NULL;
  }
  return _mysql["lang"];
}


function mysql_get_status()
{
  if (isnull(_mysql))
  {
    display("mysql_get_status: need to call mysql_open first.\n");
    return NULL;
  }
  return _mysql["status"];
}


function mysql_is_proto41_supported()
{
  if (isnull(_mysql))
  {
    display("mysql_is_proto41_supported: need to call mysql_open first.\n");
    return NULL;
  }

  if (mysql_get_caps() & 512) return TRUE;
  else return FALSE;
}


function mysql_is_ok_packet(packet)
{
  if (isnull(packet) || packet["len"] < 1)
  {
    display("mysql_is_ok_packet: 'packet' argument is missing or invalid.\n");
    return NULL;
  }
  if (getbyte(blob:packet["data"], pos:0) == 0) return TRUE;
  else return FALSE;
}


function mysql_is_error_packet(packet)
{
  if (isnull(packet) || packet["len"] < 1)
  {
    display("mysql_is_error_packet: 'packet' argument is missing or invalid.\n");
    return NULL;
  }
  if (getbyte(blob:packet["data"], pos:0) == 0xff) return TRUE;
  else return FALSE;
}


function mysql_get_null_string(blob, pos)
{
  local_var i, tmp;

  if (isnull(pos)) pos = 0;

  tmp = NULL;
  for (i=pos; i<strlen(blob); i++)
  {
    if (ord(blob[i]) != 0)
      tmp += blob[i];
    else
      break;
  }
  return tmp;
}


function mysql_get_last_error()
{
  if (isnull(_mysql))
  {
    display("mysql_get_last_error: need to call mysql_open first.\n");
    return NULL;
  }

  if (isnull(_mysql["err"])) return NULL;
  else return mysql_parse_error_packet(_mysql["err"]);
}


function mysql_parse_error_packet(packet)
{
  local_var err;

  if (isnull(packet) || packet["len"] < 1)
  {
    display("mysql_parse_error_packet: 'packet' argument is missing or invalid.\n");
    return NULL;
  }

  err = NULL;
  if (mysql_is_error_packet(packet:packet))
  {
    err["num"] = getword(blob:packet["data"], pos:1);
    # Version 4.1.
    if (getbyte(blob:packet["data"], pos:3) == ord("#"))
    {
      err["state"] = substr(packet["data"], 4, 8);
      err["msg"] = substr(packet["data"], 9);
    }
    # Pre-version 4.1.
    else
    {
      err["state"] = NULL;
      err["msg"] = substr(packet["data"], 3);
    }
  }
  return err;
}


# nb: this function is used for 4.1 authentication.
function mysql_get_scramble(pass, msg)
{
  local_var i, l, scramble, stage1, stage2;

  if (isnull(pass))
  {
    display("mysql_get_scramble: 'pass' argument is missing.\n");
    return NULL;
  }
  if (isnull(msg))
  {
    display("mysql_get_scramble: 'msg' argument is missing.\n");
    return NULL;
  }

  stage1 = SHA1(pass);
  stage2 = SHA1(stage1);
  scramble = SHA1(string(msg, stage2));
  l = strlen(scramble);
  for (i=0; i<l; i++)
    scramble[i] = raw_string(ord(stage1[i]) ^ ord(scramble[i]));
  return scramble;
}


# NB: this is not yet working -- seed calculation can overflow.
function mysql_get_scramble323(pass, msg, proto)
{
  local_var extra, hash_msg, hash_pass, i, l, max_value, scramble, seed1, seed2;

  if (isnull(pass))
  {
    display("mysql_get_scramble323: 'pass' argument is missing.\n");
    return NULL;
  }
  if (isnull(msg))
  {
    display("mysql_get_scramble323: 'msg' argument is missing.\n");
    return NULL;
  }
  if (isnull(proto))
  {
    display("mysql_get_scramble323: 'proto' argument is missing.\n");
    return NULL;
  }

  scramble = "";
  l = strlen(pass);
  if (l && strlen(msg))
  {
    hash_pass = mysql_hash_password(pass:pass);
    hash_msg  = mysql_hash_password(pass:msg);

    if (proto == 10)
    {
      max_value = 0x3FFFFFFF;
      seed1 = (hash_pass[0] ^ hash_msg[0]) % max_value;
      seed2 = (hash_pass[1] ^ hash_msg[1]) % max_value;
    }
    else 
    {
      max_value = 0x01FFFFFF;
      seed1 = (hash_pass[0] ^ hash_msg[0]) % max_value;
      seed2 = int(seed1/2);
    }

    for (i=0; i<=l; i++)
    {
      # NB: this overflows
      seed1 = int(seed1*3 + seed2) % max_value;
      seed2 = int(seed1 + seed2 + 33) % max_value;
      scramble += raw_string(int(seed1 / (max_value/31)) + 64);
    }
    if (proto == 10)
    {
      seed1 = int(seed1*3 + seed2) % max_value;
      seed2 = int(seed1 + seed2 + 33) % max_value;
      extra = int((seed1 / max_value)*31);

      for (i=0; i<l; i++)
        scramble[i] = raw_string(ord(scramble[i]) ^ extra);
    }
  }
  return scramble;
}


function mysql_hash_password(pass)
{
  local_var add, i, l, nr, nr2, result, tmp;

  if (isnull(pass))
  {
    display("mysql_hash_password: 'pass' argument is missing.\n");
    return NULL;
  }

  nr = 1345345333;
  add = 7;
  nr2 = 0x12345671;

  l = strlen(pass);
  for (i=0; i<l; i++)
  {
    tmp = ord(pass[i]);
    if (tmp != ' ' && tmp != '\t')
    {
      nr = nr ^ (((nr & 63) + add) * tmp)+ (nr << 8);
      nr2 += (nr2 << 8) ^ nr;
      add += tmp;
    }
  }
  result[0] = nr & ((1 << 31) -1);
  result[1] = nr2 & ((1 << 31) -1);

  return result;
}
