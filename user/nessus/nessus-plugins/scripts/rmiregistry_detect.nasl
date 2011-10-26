#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

An RMI registry is listening on the remote host. 

Description :

The remote host is running an RMI registry, which acts as a bootstrap
naming service for registering and retrieving remote objects with
simple names in the Java Remote Method Invocation (RMI) system. 

See also :

http://java.sun.com/j2se/1.5.0/docs/guide/rmi/spec/rmiTOC.html
http://java.sun.com/j2se/1.5.0/docs/guide/rmi/spec/rmi-protocol3.html

Risk factor :

None";


if (description)
{
  script_id(22227);
  script_version("$Revision: 1.4 $");

  script_name(english:"RMI Registry Detection");
  script_summary(english:"Detects an RMI registry");

  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 1099);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests) {
  port = get_unknown_svc(1099);
  if (!port) exit(0);
}
else port = 1099;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Probe the service.
#
# nb: with the stream procotol, an endpoint must respond with an
#     endpoint identifier.
req1 = "JRMI" +                        # magic
  mkword(2) +                          # version
  mkbyte(0x4b);                        # protocol (0x4b => stream protocol)
send(socket:soc, data:req1);
res = recv(socket:soc, length:64);


# If...
if (
  # the response is long enough and...
  strlen(res) > 6 &&
  # it's a ProtocolAck and...
  getbyte(blob:res, pos:0) == 0x4e &&
  # it contains room for an endpoint identifier
  getword(blob:res, pos:1) + 7 == strlen(res)
)
{
  # Discover the names bound to the registry.
  host = this_host();
  req2_1 =                             # client's default endpoint
    mkword(strlen(host)) + host +      #   hostname
    mkword(0) + mkword(0);             #   port
  req2_2 = 
    mkbyte(0x50) +                     # message (0x50 => CallData)
                                       # serialized object
      mkword(0xaced) +                 #   stream magic
      mkword(0x05) +                   #   stream version
      mkbyte(0x77) +                   #   blockdata
        mkbyte(0x22) +                 #     size
        raw_string(                    #     data
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
          0x00, 0x01, 0x44, 0x15, 0x4d, 0xc9, 0xd4, 0xe6, 
          0x3b, 0xdf
        );
  send(socket:soc, data:req2_1+req2_2);
  res = recv(socket:soc, length:4096);
  close(soc);

  # If it looks like a valid response...
  if (
    "java.lang.String" >< res &&
    "java.rmi.NoSuchObjectException" >!< res
  )
  {
    info = "";

    # Determine the number of names.
    data = strstr(res, "java.lang.String") - "java.lang.String";
    i = stridx(data, "t");
    if (i >= 0) n = getword(blob:data, pos:i-2);
    else n = 0;

    if (n > 0)
    {
      # Iterate over each name.
      j = i;
      for (i=0; i<n; i++)
      {
        if (data[j++] != 't') break;   # 't' => string.
        l = getword(blob:data, pos:j);
        if (l > 0 && l+j+2 <= strlen(data))
        {
          name = substr(data, j+2, j+2+l-1);
          j += l+2;
        }
        else break;

        # Get the remote reference for the name.
        soc = open_sock_tcp(port);
        if (soc) 
        {
          send(socket:soc, data:req1);
          res = recv(socket:soc, length:64);
          if (
            strlen(res) > 6 &&
            getbyte(blob:res, pos:0) == 0x4e &&
            getword(blob:res, pos:1) + 7 == strlen(res)
          )
          {
            req2_2 =
              mkbyte(0x50) +           # message (0x50 => CallData)
                                       # serialized object
              mkword(0xaced) +         #   stream magic
              mkword(0x05) +           #   stream version
              mkbyte(0x77) +           #   blockdata
                mkbyte(0x22) +         #     size
                raw_string(            #     data
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                  0x00, 0x02, 0x44, 0x15, 0x4d, 0xc9, 0xd4, 0xe6, 
                  0x3b, 0xdf
                ) +
              mkbyte(0x74) +           #   string
                mkword(strlen(name)) + #   size
                name;                  #     data
            send(socket:soc, data:req2_1+req2_2);
            res = recv(socket:soc, length:4096);
            close(soc);

            # If ...
            if (
              # it's a return data and...
              getbyte(blob:res, pos:0) == 0x51 &&
              # it's a serialized object and...
              getword(blob:res, pos:1) == 0xaced &&
              # it's an RMI server and
              "java.rmi.server" >< res &&
              # it has a reference to the remote object
              "UnicastRef" >< res
            )
            {
              data2 = strstr(res, "UnicastRef") - "UnicastRef";
              # nb: adjust slightly if the object is of the UnicastRef2 type.
              if (data2[0] == "2") data2 = substr(data2, 2);
              l = getword(blob:data2, pos:0);
              if (l > 0 && (l+2-1+3 <= strlen(data2)))
              {
                ref_host = substr(data2, 2, l+2-1);
                ref_port = getword(blob:data2, pos:l+2-1+3);

                if (ref_host == get_host_ip())
                {
                  set_kb_item(name:"Services/rmi/" + ref_port + "/name", value:name);
                  set_kb_item(name:"Services/rmi/" + ref_port + "/ref", value:hexstr(substr(res, 5)));
                }

                info += "  rmi://" + ref_host + ":" + ref_port + "/" + name + '\n';
              }
              else break;
            }
          }
        }
      }
    }

    if (report_verbosity)
    {
      if (info)
        report = string(
          desc,
          "\n\n",
          "Plugin output :\n",
          "\n",
          "Here is a list of objects the remote RMI registry is currently\n",
          "aware of :\n",
          "\n",
          info
        );
      else report = string(
          desc,
          "\n\n",
          "Plugin output :\n",
          "\n",
          "The remote RMI registry currently does not have information about\n",
          "any objects.\n"
        );
    }
    else report = desc;

    # Register and report the service.
    register_service(port:port, ipproto:"tcp", proto:"rmi_registry");
    security_note(port:port, data:report);
  }
}
