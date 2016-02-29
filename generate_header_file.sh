#!/bin/bash

arch="`/usr/bin/arch`"
tmp="`/bin/mktemp`"

if [ ${arch} = "x86_64" ]; then
    src="https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/entry/syscalls/syscall_64.tbl"
    /usr/bin/curl -s ${src} | /bin/egrep -v '^(#|$)' | /bin/egrep -v 'x32' > ${tmp}
elif [ ${arch} = "i686" ]; then
    src="https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/entry/syscalls/syscall_32.tbl"
    /usr/bin/curl -s ${src} | /bin/egrep -v '^(#|$)' | /bin/egrep '(common|i386)' > ${tmp}
else
    exit 1
fi

echo "typedef struct{"
echo -e "\t" "char* syscall_name;"
echo -e "\t" "int syscall_num;"
echo "} syscall_t;"
echo

echo "const char* arch=\"${arch}\";"
echo "const char* syslist_src=\"${src}\";"
echo

echo "syscall_t syscall_table[] = {"
while read i; do
    sc="`echo $i | awk '{print $3}'`"
    si="`echo $i | awk '{print $1}'`"
    echo -e "\t{\"$sc\", $si},"
done < ${tmp}
echo -e "\t{NULL, -1}"
echo "};"

/bin/rm ${tmp}

exit 0
