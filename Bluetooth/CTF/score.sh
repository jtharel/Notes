gatttool -b 30:AE:A4:7D:69:BE --char-read -a 0x002a|awk -F':' '{print $2}'|tr -d ' '|xxd -r -p;printf '\n'
