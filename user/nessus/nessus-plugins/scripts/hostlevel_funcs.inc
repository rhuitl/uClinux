#TRUSTED a43b133c0eb317a99c6cb4120a4c047860f99f7fa56741e92926d9e7c62f82aa486fe86b7a5ed548adab621a13cbeb1d278f318b435e57e2c75cd40cbee28b5e40e62d2d5c6fb84405a9ebd92970771377e23d22101c3ace231536da33c66933d7276acfc81ca3ee52b566dd8af950e2fd185633b34f29fd0487415e529afcd7af5492fc62fe4fdaf073d943810c0e75942035f7dd57c0280d1a97d845177a18ae5d267cb98ed5ffdec301a15b39cfd0b62bc27bf953c52f57f66528c62f77c71cea9c4d7d744503a115899c1f6bdf0c022a1d446f5c4d349a68eb139b67a6733d6a53bf104cd230bdab645240826553863ac5dc868ef1ac597a2d2dc08f7ab5976d4c0b02f3ca0338616bb6c2ddd479b4fac7467ba9d6c0951d9276b11b7600e5bc0728f4b672138f2dbddc2f7063a5e99b4a16eab0e24959de0d44dc97296210b6e23018d33a8a447f92ff7bf1ca1f1f2a7c3a73cdbc38acd215954ffeeed04e7281d2f34035dde94950dc7b35f6516bf6a5309a82d9dfb8a1ba2b9e5a9876a0ea8684d6e17b80bc2f607a136af90be9e73565ce953410d9f6fa9f8a89ea508dba09d736125c65b6ba18db22570acff5c325d5a7481e7752dd259280ec0fb377d7d091881b3e7a7a85813e7875e0f072184e2c52a9c3626d240fb40482a8372e732b286f80e9c5b009ee2861aae279e32fb82b00b1301b556780a48c5823c2
#
# (C) Michel Arboi
# Portions (C) Tenable Network Security, Inc.
#

global_var report_verbosity, port_g, login, pass;
global_var	info_t, sock_g, sep, c;

INFO_LOCAL  = 1; 
INFO_SSH    = 2; 
INFO_RSH    = 3; 
INFO_REXEC  = 4; 
INFO_RLOGIN = 5; 
INFO_TELNET = 6;



function telnet_open_cnx(port, login, pass)
{
 local_var	s, res;

 if ( ! get_port_state(port) ) return;
 s = open_sock_tcp(port);
 if (! s) return;

 res = telnet_negotiate(socket: s);
 if (strlen(res) == 0)
 {
  close(s);
  return;
 }
 send(socket: s, data: strcat(login, '\r\n'));
 res = recv_until(socket: s, pattern: "[pP]assword:");
 if (strlen(res) == 0)
 {
  close(s);
  return;
 }
 send(socket: s, data: strcat(pass, '\r\n'));
 res = recv_until(socket: s, pattern: '[$#%>] ');
 if (strlen(res) == 0)
 {
  close(s);
  return;
 }
 send(socket: s, data: 'thisisnotaknowncommand'+rand()+'\r\n');
 res = recv_until(socket: s, pattern: '[$#%>] ');
#debug_print('Bad command => ', res);
 if ('thisisnotaknowncommand' >!< res)
 {
  close(s);
  return;
 }
 return s;
}

function send_rexec(port, login, pass, cmd)
{
  local_var	s, buf;

  if ( ! get_port_state(port) ) return;
  s = open_priv_sock_tcp(dport: port);
  if (! s) return;
  send(socket: s, data: '\0');    # No separate channel for error :-(
  send(socket: s, data: strcat(login, '\0', pass, '\0', cmd, '\0'));
  buf = recv(socket: s, length: 1);  # 0 if OK?
  if (ord(buf[0]) > 0)
  {
   close(s);
   return;
  }
  buf = recv(socket: s, length: 1024*1024);
  close(s);
#debug_print('send_rexec: cmd = ', cmd, '\nbuf = \n', buf, '\n\n');
  return buf;
}

function rlogin(port, login, pass, from)
{
 local_var	s, r;

 if ( ! get_port_state(port) ) return;
 s = open_priv_sock_tcp(dport: port);
 if (!s) return;
 if (! from) from = 'root';
 send(socket: s, data: '\0');
 send(socket: s, data: strcat(from, '\0', login, '\0raw/38400\0'));
 r = recv(socket: s, length: 1);
 if (r != '\0') { close(s); return; }
 r = recv(socket: s, length: 1024*1024);
 if (r =~ 'Password *: *$')
 {
  send(socket: s, data: pass + '\r');
  r = recv(socket: s, length: 1024*1024);
  display("'", ord(r[0]), "' (r)\n");
  if (r =~ 'Password *: *$')
  {
   close(s);
   return;
  }
 }
 return s;
}

function send_rsh(port, login, from, cmd)
{
 local_var	s, buf;

 if (! from) from = 'root';
 s = open_priv_sock_tcp(dport: port);
 if (! s) return;
 send(socket: s, data: '0\0');	# No separate channel for error :-(
 send(socket: s, data: strcat(from, '\0', login, '\0', cmd, '\0'));
 buf = recv(socket: s, length: 1);  # 0 if OK?
 if (ord(buf[0]) > 0)
 {
  close(s);
  return;
 }
 buf = recv(socket: s, length: 1024*1024);
 close(s);
 return buf;
}


function info_send_cmd(cmd)
{
 local_var	buf, f;

#debug_print('info_send_cmd: cmd=', cmd);

 if (info_t == INFO_LOCAL)
 {
  if (match(string: cmd, pattern: "cat *"))
  {
   f = substr(cmd, 4);
   if (! file_stat(f))
   {
#debug_print('info_send_cmd: ', f, ' does not exist or cannot be read\n');
    return NULL;
   }
   else
    return fread(f);
  }
  else
  {
   if ("'" >< cmd) sep = '"';
   else sep = "'";
   return pread(cmd: "/bin/sh", argv: make_list("sh", "-c", cmd));
  }
 }

 if (info_t == INFO_SSH)
 {
  return ssh_cmd(socket: sock_g, cmd: cmd, timeout: 120);
 }

 if (info_t == INFO_RSH)
 {
  return send_rsh(login: login, port: port_g, cmd:cmd);
 }
 if (info_t == INFO_REXEC)
 {
  return send_rexec(login: login, pass: pass, port: port_g, cmd:cmd);
 }

 if (info_t == INFO_TELNET)
 {
  send(socket: sock_g, data: 
  # Yes! Two spaces (or more) are necessary
    strcat('echo NESSUS  START; ', cmd, ' 2>/dev/null; echo NESSUS  END\r\n'));
  # But just one space here!
  buf = recv_until(socket: sock_g, pattern: 'NESSUS END');
#debug_print('buf=>>>\n', buf, '<<<\n');
  recv_until(socket: sock_g, pattern: '[%$#>] ');
  # Only one space here!
  buf = strstr(buf, 'NESSUS START');
#debug_print('buf=>>>\n', buf, '<<<\n');
  c = buf - 'NESSUS START'; 
  while (c[0] == '\r' || c[0] == '\n' || c[0] == ' ' || c[0] == '\t')
   c = substr(c, 1);
  c = chomp(c - 'NESSUS END');
#if (c == buf) debug_print('info_send_cmd: could not extract command output from: ', buf);
#debug_print('c=>>>\n', c, '<<<\n');
  return c;
 }

 #log_print('info_send_cmd: unhandled case info_t=', info_t, ' - cmd=', cmd, '\n');
 return;
}


function set_globals()
{
 local_var opt;
 opt = get_kb_item("global_settings/report_verbosity");

 if (opt )
        {
        if ("Verbose" >< opt ) report_verbosity = 2;
        else if ("Normal" >< opt ) report_verbosity = 1;
        else if ("Quiet" >< opt ) report_verbosity = 0;
        }
} 


set_globals();

