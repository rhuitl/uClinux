# -*- Fundamental -*-
# 
# (C) Michel Arboi 2003
#

# 
# "ping pong" is possible with any service. However, it is really dangerous
# against chargen or echo. Some "simple services" do not answer if the
# source port is privileged, thus preventing the exploitation.
# 
function udp_ping_pong(port, data, answer)
{
  local_var	s, r1, r2;

  if (!port || ! get_udp_port_state(port)) return 0;

  if (! answer)  # or isnull(answer)?
  {
    s = open_sock_udp(port);
    if (!s)  return 0;
    send(socket: s, data: data);
    r1 = recv(socket: s, length: 1024);
    close(s);
  }
  else
    r1 = answer;

  if (! r1) return 0;	# Cannot test

  s = open_priv_sock_udp(dport: port);
  if (!s)  return 0;
  send(socket: s, data: data);
  r2 = recv(socket: s, length: 1024);
  close(s);
  if (! r2) return 0;	# Not vulnerable
  #display("udp_ping_pong: port=", port, " - the service answers only to non privileged sockets\n");
  return 1;    
}
