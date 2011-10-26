#include <unistd.h>
#include <stdio.h>
#include "conffile.h"

int bla(char *args)
{
	printf("bla called: %s\n", args);
	return 0;
}
int main()
{
	config_entry_t e,f;
	memset(&e, 0, sizeof(config_entry_t));
	strcpy(e.key, "zeile");
	e.u.parser = bla;
	e.type = CONFIG_TYPE_CALLBACK;
	config_register_key(&e);

	strcpy(f.key, "spalte");
	f.type = CONFIG_TYPE_STRING;
	f.options |= CONFIG_OPT_MANDATORY;
	f.u.str.string = (char *) malloc(100);
	f.u.str.maxlen = 99;
	config_register_key(&f);

	config_parse_file("test.txt");
	printf("SPALTE: %s\n", f.u.str.string);

	exit(0);
}
