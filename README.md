# HaveIBeenPwnedOffline
Search the password list from haveibeenpwned.com locally

## Usage

Download the SHA-1 file (orderered by hash) 
from https://haveibeenpwned.com/Passwords. 
This file you download is a 12 GB 7zip file which 
contains a 25GB txt file.

Place it in the same folder as `binary_search.py`. 
Currently it should be named 
`pwned-passwords-sha1-ordered-by-hash-v4.txt`. If it has this 
name you do not need to supply a filename for the script to
search in.

After that run the python script. It accepts a filename that has each hash to be tested on a new line. On Ubuntu it would look like this:

```shell
python binary_search.py hashList.txt
```

