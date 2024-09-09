awk to grab the next 20 characters everytime id":" appears in the file output.txt
```
awk -F'id":"' '{for (i=2; i<=NF; i++) print substr($i, 1, 20)}' output.txt
```
