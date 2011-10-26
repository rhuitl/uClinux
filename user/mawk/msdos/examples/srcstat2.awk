# Ben Myers <0003571400@mcimail.com>

# Sum up number, line count, and sizes of SOURCE files in current directory
# run with 
#       bmawk -fsrcsize.awk workfile
# or similar command syntax with your awk program
# where workfile is a work file
BEGIN {
# redirection done by shelled command
system("dir *.* >workfile")
ssize = 0   # size accumulator
slines = 0  # line counter
scount = 0  # obj counter
exit
}
END {
# Now read workfile back in
    while (getline < "workfile" > 0) {
    if ($2 == "C" || $2 == "H" || $2 == "CPP" || $2 == "HPP")  {
	filename = sprintf("%s.%s", $1, $2)
	ssize += $3
	while (getline < filename > 0) {slines++}
	scount++
	}
    }
print scount " files, " slines " lines, total size " ssize " bytes"
system("del workfile")
}
