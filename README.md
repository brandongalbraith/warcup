# warcup
internet archive warc uploader

Source: https://gist.github.com/ivan/079530350ac94851d581b55b1d372440

Run with:

```
#!/bin/bash

export ITEM_PART_COUNT_FILE=$HOME/item-part-count-file
export SUCCESSFUL_UPLOADS_FILE=$HOME/successful-warc-uploads
export S3_URL=https://s3.us.archive.org
export IA_ITEM_TITLE=WARC:
export IA_ITEM_PREFIX=warc
export IA_ACCESS=XXX
export IA_AUTH=$IA_ACCESS:YYY

~/ia_warc_uploader.py ~/warcs-for-ia
```

(replace XXX and YYY)

and use with an aliased grab-site:

```
alias grab-site="~/gs-venv/bin/grab-site --finished-warc-dir=$HOME/warcs-for-ia"
```
