# -*- Fundamental -*-
#
# (C) 2002 Michel Arboi <arboi@alussinan.org>
# $Revision: 1.30 $

function smtp_close(socket)
{
  send(socket: socket, data: 'QUIT\r\n');
  smtp_recv_line(socket: socket);
  close(socket);
}

function smtp_open(port, helo)
{
  local_var	soc, data;

  soc = open_sock_tcp(port);
  if (! soc) return NULL;

  data = smtp_recv_banner(socket:soc);
  if (! data)
  {
    smtp_close(socket: soc);
    return NULL;
  }
  
  if ( isnull(helo) ) return soc;

  send(socket:soc, data: strcat('HELO ', helo, '\r\n'));
  data = smtp_recv_line(socket: soc);
  if(! ereg(pattern:"^[2-3][0-9][0-9]", string:data))
  {
    smtp_close(socket: soc);
    return NULL;
  }

  return soc;  
}

function smtp_send_socket(socket, from, to, body)
{
  local_var buff;
  # display(string("smtp_send_socket from=", from, " to=", to, "\n"));
  # Just to be sure
  send(socket: socket, data: string("RSET\r\n"));
  buff = recv_line(socket: socket, length: 2048);
  # Here, we might test the return code
  if (from !~ ' *<.*> *') from = strcat('<', from, '>');
  send(socket: socket, data: string("MAIL FROM: ", from, "\r\n"));
  buff = recv_line(socket: socket, length: 2048);
  if (! ereg(pattern:"^2[0-9][0-9] ", string:buff)) { return (0); }
  
  if (to !~ ' *<.*> *') to = strcat('<', to, '>');
  send(socket: socket, data: string("RCPT TO: ", to, "\r\n"));
  buff = recv_line(socket: socket, length: 2048);
  if (! ereg(pattern:"^2[0-9][0-9] ", string:buff)) { return (0); }

  send(socket: socket, data: string("DATA\r\n"));
  buff = recv_line(socket: socket, length: 2048);
  if (! ereg(pattern:"^3[0-9][0-9] ", string:buff)) { return (0); }

  # Make sure that every line ends up with \r\n
  # This is not useful yet, as only two scripts send data to the SMTP server
  #body = ereg_replace(string: body, pattern: string("([^\r])\n"), replace: string("\\1\r\n"));
  send(socket: socket, data: body);
  send(socket: socket, data: string("\r\n.\r\n"));
  buff = recv_line(socket: socket, length: 2048);
  if (! ereg(pattern:"^2[0-9][0-9] ", string:buff)) { return (0); }
  return(1);
}

function smtp_send_port(port, from, to, body)
{
  local_var s, buff, ret, hostname;
  s = open_sock_tcp(port);
  if (! s) return (0);

  buff = recv_line(socket: s, length: 2048);
  hostname = get_kb_item('smtp/'+ port + '/helo');
  if (! hostname) hostname = 'nessus';
  send(socket: s, data: strcat('HELO ', hostname, '\r\n'));
  buff = recv_line(socket: s, length: 2048);
  # We should test the code
  ret = smtp_send_socket(socket: s, from: from, to: to, body: body);
  send(socket: s, data: string("QUIT\r\n"));
  close(s);
  return (ret);
}

function smtp_from_header()
{
 local_var fromaddr;
 fromaddr = get_kb_item("SMTP/headers/From");
 if (!fromaddr) fromaddr = "nessus@example.com";
 return (fromaddr);
}

function smtp_to_header()
{
 local_var toaddr;
 toaddr = get_kb_item("SMTP/headers/To");
 if (!toaddr) toaddr = string("postmaster@[", get_host_ip(), "]");
 return (toaddr);
}

function get_smtp_banner(port)
{
  local_var sb, banner, soc;
  
  sb = string("smtp/banner/", port);
  banner = get_kb_item(sb);
  if(banner) return (banner);
  if ( get_kb_item("smtp/" + port + "/broken") ) 
	return NULL;

  if(! get_port_state(port)) return (0);
  soc = open_sock_tcp(port);
  if (! soc) {
	set_kb_item(name:"smtp/" + port + "/broken", value:TRUE);
	return NULL;
	}
  banner =  smtp_recv_banner(socket: soc);
  close(soc);
  if(! banner ) {
	set_kb_item(name:"smtp/" + port + "/broken", value:TRUE);
	return NULL;
	}
	
  
  if ( defined_func("replace_kb_item") )
  	replace_kb_item(name: sb, value: banner);
  else
  	set_kb_item(name: sb, value: banner);
  return(banner);
}


function smtp_recv_line(socket, code, retry, last)
{
 local_var ret, n, r, pat;
 
 if (isnull(code))
   pat = "^[0-9][0-9][0-9]-";
 else
   pat = strcat("^", code, "-");

 ret = "";
 r = recv_line(socket:socket, length:4096);
 #
 n = 0;
 while (! r && n ++ < retry)
   r = recv_line(socket:socket, length:4096);
 #
 n = 0;
 ret = r;
 if(strlen(r) < 4) 
  return r;
  
 while(ereg(pattern: pat, string:r))
 {
  n = n + 1;
  r = recv_line(socket:socket, length:4096);
  if (strlen(r) == 0) break;
  if (n > 512)
   return NULL;
  if (last) ret = r;
  else      ret = strcat(ret, r);
 }
 return ret;
}

function smtp_recv_banner(socket)
{
  return smtp_recv_line(socket: socket, code: "220");
}

