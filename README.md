# Yara Dulicate Rules Removal 
Read a Yara file and get all "imports" and "rules" and remove the duplicate, then write to another file

### Usage:
![alt text](https://github.com/salehmuhaysin/Yara_Duplicate_Rules/blob/master/Selection_066.png?raw=true)

#### Arguments:

```
usage: Python script tool remove duplicate rules from Yara file
       [-h] -i IN_FILE -o OUT_FILE [-v] [-nh]

optional arguments:
  -h, --help   show this help message and exit
  -v           print more details
  -nh          Dont print the header

required arguments:
  -i IN_FILE   Input Yara file
  -o OUT_FILE  output Yara file with no duplication
```


### Output

the output will be written to the <OUT_FILE> file contain the "imports" and "rules"

NOTE:

the output is only rules and imports, so any comments outside the rule body will not exported,
example:
```
/*
    This is a multi-line comment ... (not incuded)
*/
Import “pe”
rule CommentExample   // ... and this is single-line comment
{
    condition:
       false  // just an dummy rule, don't do this
} // rule end (not included)
```

