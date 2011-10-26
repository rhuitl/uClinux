/* Module with version sections in it */

const char vermagic[] __attribute__((section("__vermagic"))) = "my version magic";
const char modversions[] __attribute__((section("__versions"))) = "my versions";
