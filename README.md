# check-enc

Python script that uses character frequency analysis to determine likely encodings of opaque files.  Can be useful in CTF competitions.


# Features
* Attempts the following encodings:
    * hex_codec
    * base64_codec
    * rot_13
    * utf_8
    * utf_16_be
    * utf_16_le
    * bz2
    * zip
    * idna
    * palmos
    * punycode
    * quopri_codec
    * utf_7
    * base32
    * uuencode
    * quotable
    * binhex4
    * yenc
* Attempts permutations of any 2 of the above-listed enodings


# Prerequisites
To install necessary prerequisites on Ubuntu:

    sudo apt-get install python3-yenc


# Usage
```
Purpose:  Attempts to decode/encode unknown data

Prereq:   Python package 'yenc'.  On Debian systems, this can be installed
          using `sudo apt-get install python-yenc`

Usage:    checkenc.py [-d|-e] [-1] [-a] [-v] -f <file>
              reads data from file
          checkenc.py [-d|-e] [-1] [-a] [-v] '<data>'
              reads data from last non-option argument
          checkenc.py -h
              displays this help

Options:  -d  Decode data (default)

          -e  Encode data (if absent, -d is assumed)
          
          -1  Only performs one decoding/encoding pass on data (if absent,
              default behavior is to attempt all permutations of any two
              encodings).  This will decrease running time for large data
              sets.
          
          -a  Display all results (if absent, only top 20 are displayed)
          
          -v  Verbose mode
          
Output:   One row is displayed for each result.  There are three columns in
          each row:
              1)  Score.  higher (more positive) is better.  The score will
                  usually be negative.
              2)  Encoding used (or combination of encodings).  "Caesar_XXX"
                  is a Caesar cipher with each byte incremented by XXX.
              3)  Result after de/encoding.  Special characters will be escaped
                  appropriately.
```


### Example usage
On Ubuntu:
```
user@computer:~$ ./checkenc.py -f base64.bin 
First pass complete.  Now trying permutating each result...
Top 20 results, worst to best:
-644.75 <base64_codec + quotable> "'ThisIsATest\\n'"
-603.41 <utf_8> u'VGhpc0lzQVRlc3QK\n'
-603.41 <idna> u'VGhpc0lzQVRlc3QK\n'
-603.41 <palmos> u'VGhpc0lzQVRlc3QK\n'
-603.41 <utf_7> u'VGhpc0lzQVRlc3QK\n'
-597.33 <quopri_codec> 'VGhpc0lzQVRlc3QK\n'
-597.33 <quotable> 'VGhpc0lzQVRlc3QK\n'
-590.33 <rot_13> u'ITucp0ymDIEyp3DX\n'
-585.33 <Caesar_255> 'UFgob/kyPUQkb2PJ\t'
-584.38 <base64_codec + Caesar_4> '+XlmwMwEXiwx`r+'
-582.37 <base64_codec + Caesar_254> '%RfgqGq?RcqrZl%'
-577.70 <base64_codec + Caesar_2> ')VjkuKuCVguv^p)'
-576.05 <base64_codec + Caesar_253> '$QefpFp>QbpqYk$'
-569.52 <base64_codec + Caesar_3> '*WklvLvDWhvw_q*'
-569.10 <base64_codec + Caesar_252> '#PdeoEo=PaopXj#'
-557.71 <base64_codec + Caesar_1> '(UijtJtBUftu]o('
-494.86 <base64_codec + Caesar_5> ',YmnxNxFYjxyas,'
-483.99 <base64_codec + Caesar_6> '-ZnoyOyGZkyzbt-'
-344.75 <base64_codec> 'ThisIsATest\n'

user@computer:~$ ./checkenc.py -f base64_plus_caesar.bin 
First pass complete.  Now trying permutating each result...
Top 20 results, worst to best:
-671.46 <Caesar_246> "M>_gZ'cqHMIcZ*HB"
-662.67 <Caesar_249> 'PAbj]*ftKPLf]-KE'
-662.13 <Caesar_251> 'RCdl_,hvMRNh_/MG'
-659.41 <Caesar_245> 'L=^fY&bpGLHbY)GA'
-653.25 <Caesar_252> 'SDem`-iwNSOi`0NH'
-601.57 <rot_13> u'JUvdq1z{EJFzq4EY'
-582.36 <Caesar_1> 'XIjre2n|SXTne5SM'
-582.33 <Caesar_3> 'ZKltg4p~UZVpg7UO'
-571.06 <utf_8> u'WHiqd1m{RWSmd4RL'
-571.06 <idna> u'WHiqd1m{RWSmd4RL'
-571.06 <palmos> u'WHiqd1m{RWSmd4RL'
-571.06 <utf_7> u'WHiqd1m{RWSmd4RL'
-564.99 <quopri_codec> 'WHiqd1m{RWSmd4RL'
-564.99 <quotable> 'WHiqd1m{RWSmd4RL'
-564.16 <Caesar_2> 'YJksf3o}TYUof6TN'
-491.93 <Caesar_255> 'VGhpc0lzQVRlc3QK'
-482.75 <Caesar_254> 'UFgob/kyPUQkb2PJ'
-473.34 <Caesar_253> 'TEfna.jxOTPja1OI'
-344.75 <Caesar_255 + base64_codec> 'ThisIsATest\n'
```

