#TRUSTED 36aba1ca831e52abb0ce90879260ef8fb10c8ca1270c8ba1ee72d476e9cf29a07255d718091559b8580eee87a16cf20ba85bc845f02eabe7b421e29e4737393fee8d6bcd9f7255e3164d436cc72e2e770d08478274d6d4c82e6b3d95a7b2aab29ab573d90d78b674a4467d4a6ba3f8acc6b8b233f094718c4340af56db6070dcf6a3b131200a5f136e842b8e60720fb3d913de6b811bdbc3d51dd61b2d5226512bac2fcee02ac55b134d3416e47f1c53b23b9f41bbbb2f9de7de366323cf3869a16a0dc1b8c5d86bda7b96788bcef9f23c173b20e95030e4b70b486e1d8bd92c673d87f1458b9766358921fd0cd13d38c889bf6f1de95612802a62c9ff6fba89ec9875d8a583f978daabbe81d5e9c8e314db2463e66df36574ef953d6c2bdf7c7369571b51e040aaf3f01d38f5bf1e509a85463fb2ade75158811d46e2effff5ff6baededc7f46beb52a63e46c8f55b248b93d3e0f0abdb6136905611a3096146a9504e7f434b55cd19711cd407d5bd71046af07414fe19f140177c449847dd4288c88ebee13dff774fac4cbed688d671ffe84f91571daf75ae299cebf4d4b57aa1207f924b1c2299beaac65ba62bcc089d5e45b8c2784530d0a93ce4d76acb9a6309fadbe3caeb79b2a9999c3a81c3143725b9d6d6fbc189d5f826a6cc8671ae800411148e55aaf564d200341b541084c290fa5edca41f44a9af4655cd9cacd
#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra") ) exit(0);


if(description)
{
 script_id(15882);
 script_version ("1.2");
 name["english"] = "Hydra: rexec";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs Hydra to find rexec accounts & passwords by brute force.

See the section 'plugins options' to configure it
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Brute force rexec authentication with Hydra";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 script_timeout(0);
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file");
 script_require_ports("Services/rexecd", 512);
 script_dependencies("hydra_options.nasl", "find_service.nes", "rexecd.nasl");
 exit(0);
}

#

throrough = get_kb_item("global_settings/thorough_tests");
if ("yes" >!< throrough) exit(0);
logins = get_kb_item("Secret/hydra/logins_file");
passwd = get_kb_item("Secret/hydra/passwords_file");
if (logins == NULL || passwd == NULL) exit(0);

port = get_kb_item("Services/rexecd");
if (! port) port = 512;
if (! get_port_state(port)) exit(0);

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

i = 0;
argv[i++] = "hydra";
argv[i++] = "-s"; argv[i++] = port;
argv[i++] = "-L"; argv[i++] = logins;
argv[i++] = "-P"; argv[i++] = passwd;
s = "";
if (empty) s = "n";
if (login_pass) s+= "s";
if (s)
{
  argv[i++] = "-e"; argv[i++] = s;
}
if (exit_asap) argv[i++] = "-f";
if (tr >= ENCAPS_SSLv2) argv[i++] = "-S";

if (timeout > 0)
{
  argv[i++] = "-w";
  argv[i++] = timeout;
}
if (tasks > 0)
{
  argv[i++] = "-t";
  argv[i++] = tasks;
}

argv[i++] = get_host_ip();
argv[i++] = "rexec";

report = "";
results = pread(cmd: "hydra", argv: argv, nice: 5);
foreach line (split(results))
{
  v = eregmatch(string: line, pattern: 'host:.*login: *(.*) password: *(.*)$');
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, 'login: ', l, '\tpassword: ', p, '\n');
    set_kb_item(name: 'Hydra/rexec/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    data: 'Hydra was able to break the following Rexec accounts:\n' + report);
