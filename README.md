# threat-intel

This repository contains IoCs related to Volexity public threat intelligence blog posts.

They are organised by year, and within each year, each folder relates to a specific post.

Each post approximately follows the same folder structure - some files or folders may be missing if there is no applicable data for the post.

```text
* YYYY-MM-DD - [Title]
    * indicators
        * indicators.csv
        * snort.rules
        * yara.yar
        * suricata.rules
    * scripts
        * foo.py
    * attachments
        * anything_else.txt
```

All rules provided are subject to the 2-Clause BSD License found in "LICENSE.txt"
