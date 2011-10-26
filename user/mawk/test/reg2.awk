
/[A-Za-z_][A-Za-z0-9_]*\[.*\][ \t]*=/ {cnt++}
END{print cnt}
