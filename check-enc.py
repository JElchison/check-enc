#!/usr/bin/env python3

# Name:  check-enc.py
# Purpose:  Attempts to decode/encode unknown data
# History:
#    v0.1 - Ben Britton       - Initial encodings
#    v0.2 - Jonathan Elchison - Code organization
#                             - Added exception handling
#                             - Added scoring of results based on letter frequencies
#                             - Added reporting of results
#                             - Added support for second pass
#                             - Added support for params, help text
#                             - Added support for yenc

import base64
import binascii
import codecs
import copy
import math
import sys
import yenc


# default number of results to display
numResults = 20

# create table of frequency logarithms
logs = dict()
logs['a'] = math.log(0.11602, 2)
logs['b'] = math.log(0.04702, 2)
logs['c'] = math.log(0.03511, 2)
logs['d'] = math.log(0.02670, 2)
logs['e'] = math.log(0.02000, 2)
logs['f'] = math.log(0.03779, 2)
logs['g'] = math.log(0.01950, 2)
logs['h'] = math.log(0.07232, 2)
logs['i'] = math.log(0.06286, 2)
logs['j'] = math.log(0.00631, 2)
logs['k'] = math.log(0.00690, 2)
logs['l'] = math.log(0.02705, 2)
logs['m'] = math.log(0.04374, 2)
logs['n'] = math.log(0.02365, 2)
logs['o'] = math.log(0.06264, 2)
logs['p'] = math.log(0.02545, 2)
logs['q'] = math.log(0.00173, 2)
logs['r'] = math.log(0.01653, 2)
logs['s'] = math.log(0.07755, 2)
logs['t'] = math.log(0.16671, 2)
logs['u'] = math.log(0.01487, 2)
logs['v'] = math.log(0.00619, 2)
logs['w'] = math.log(0.06661, 2)
logs['x'] = math.log(0.00005, 2)
logs['y'] = math.log(0.01620, 2)
logs['z'] = math.log(0.00050, 2)


def print_help():
    print("""Purpose:  Attempts to decode/encode unknown data

Prereq:   Python package 'yenc'.  On Debian systems, this can be installed
          using `sudo apt-get install python3-yenc`

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

          -a  Display all results (if absent, only top %d are displayed)

          -v  Verbose mode

Output:   One row is displayed for each result.  There are three columns in
          each row:
              1)  Score.  higher (more positive) is better.  The score will
                  usually be negative.
              2)  Encoding used (or combination of encodings).  "Caesar_XXX"
                  is a Caesar cipher with each byte incremented by XXX.
              3)  Result after de/encoding.  Special characters will be escaped
                  appropriately.
    """ % numResults)


def calculate_entropy(data):
    score = 0
    for char in data:
        try:
            score += logs[chr(char).lower()]
        except:
            # not a character.  subtract arbitrary amount from score.
            score -= 100
    return score


def parse_data(data, my_decode_flag, my_caesar_flag):
    my_answers = list()

    if my_decode_flag is True:

        for name in ('hex_codec', 'base64_codec', 'rot_13', 'utf_8', 'utf_16_be', 'utf_16_le', 'bz2', 'zip', 'idna', 'palmos', 'punycode', 'quopri_codec', 'utf_7'):
            try:
                result = data.decode(name)
                if verbose_flag:
                    print("%s succeeded" % name)
                my_answers.append([name, str.encode(result)])
            except Exception as ex:
                if verbose_flag:
                    print("%s FAILED: %s" % (name, ex))

        name = 'base32'
        try:
            result = base64.b32decode(data)
            if verbose_flag:
                print("%s succeeded" % name)
            my_answers.append([name, str.encode(result)])
        except Exception as ex:
            if verbose_flag:
                print("%s FAILED: %s" % (name, ex))

        name = 'uuencode'
        try:
            result = binascii.a2b_uu(data)
            if verbose_flag:
                print("%s succeeded" % name)
            my_answers.append([name, str.encode(result)])
        except Exception as ex:
            if verbose_flag:
                print("%s FAILED: %s" % (name, ex))

        name = 'quotable'
        try:
            result = binascii.a2b_qp(data)
            if verbose_flag:
                print("%s succeeded" % name)
            my_answers.append([name, str.encode(result)])
        except Exception as ex:
            if verbose_flag:
                print("%s FAILED: %s" % (name, ex))

        name = 'binhex4'
        try:
            result = binascii.rledecode_hqx(binascii.a2b_hqx(data))
            if verbose_flag:
                print("%s succeeded" % name)
            my_answers.append([name, str.encode(result)])
        except Exception as ex:
            if verbose_flag:
                print("%s FAILED: %s" % (name, ex))

        name = 'yenc'
        try:
            decoder = yenc.Decoder()
            decoder.feed(data)
            result = decoder.getDecoded()
            if verbose_flag:
                print("%s succeeded" % name)
            my_answers.append([name, str.encode(result)])
        except Exception as ex:
            if verbose_flag:
                print("%s FAILED: %s" % (name, ex))

    else:

        for name in ('hex_codec', 'base64_codec', 'rot_13', 'utf_8', 'utf_16_be', 'utf_16_le', 'bz2', 'zip', 'idna', 'palmos', 'punycode', 'quopri_codec', 'utf_7'):
            try:
                result = data.encode(name)
                if verbose_flag:
                    print("%s succeeded" % name)
                my_answers.append([name, str.encode(result)])
            except Exception as ex:
                if verbose_flag:
                    print("%s FAILED: %s" % (name, ex))

        name = 'base32'
        try:
            result = base64.b32encode(data)
            if verbose_flag:
                print("%s succeeded" % name)
            my_answers.append([name, str.encode(result)])
        except Exception as ex:
            if verbose_flag:
                print("%s FAILED: %s" % (name, ex))

        name = 'uuencode'
        try:
            result = binascii.b2a_uu(data)
            if verbose_flag:
                print("%s succeeded" % name)
            my_answers.append([name, str.encode(result)])
        except Exception as ex:
            if verbose_flag:
                print("%s FAILED: %s" % (name, ex))

        name = 'quotable'
        try:
            result = binascii.b2a_qp(data)
            if verbose_flag:
                print("%s succeeded" % name)
            my_answers.append([name, str.encode(result)])
        except Exception as ex:
            if verbose_flag:
                print("%s FAILED: %s" % (name, ex))

        name = 'binhex4'
        try:
            result = binascii.b2a_hqx(binascii.rlecode_hqx(data))
            if verbose_flag:
                print("%s succeeded" % name)
            my_answers.append([name, str.encode(result)])
        except Exception as ex:
            if verbose_flag:
                print("%s FAILED: %s" % (name, ex))

        name = 'yenc'
        try:
            encoder = yenc.Encoder()
            encoder.feed(data)
            result = encoder.getEncoded()
            if verbose_flag:
                print("%s succeeded" % name)
            my_answers.append([name, str.encode(result)])
        except Exception as ex:
            if verbose_flag:
                print("%s FAILED: %s" % (name, ex))

    if my_caesar_flag:
        for i in range(1, 256):
            my_answers.append(["Caesar_%d" % i, bytearray([((c + i) % 256) for c in data])])
            my_answers.append(["xor_%d" % i, bytearray([((c ^ i) % 256) for c in data])])

    return my_answers


# initialize parameters
decode_flag = True
verbose_flag = False
is_file = False
two_passes = True
print_all = False
in_data = ''
in_file = ''
in_filename = ''

if len(sys.argv) == 1:
    print_help()
    exit()

for arg in sys.argv[1:]:
    if arg == '-e':
        decode_flag = False
    elif arg == '-d':
        decode_flag = True
    elif arg == '-v':
        verbose_flag = True
    elif arg == '-f':
        is_file = True
    elif arg == '-1':
        two_passes = False
    elif arg == '-a':
        print_all = True
    elif arg == '-h':
        print_help()
        exit()
    else:
        if is_file:
            in_filename = arg
        else:
            in_data = str.encode(arg)

if is_file is True:
    in_file = open(in_filename, 'rb')
    in_data = in_file.read()
    in_file.close()

# do operation
answers = parse_data(in_data, decode_flag, True)

if two_passes:
    print("First pass complete.  Now trying permutating each result...")
    # try "2-dimensional" operation (perform parse_data() on each answer)
    answers_orig = copy.copy(answers)
    for answer in answers_orig:
        # only do Caesar once
        if answer[0].find('Caesar') == -1:
            newAnswers = parse_data(answer[1], decode_flag, True)
        else:
            newAnswers = parse_data(answer[1], decode_flag, False)
        for newAnswer in newAnswers:
            newAnswer[0] = "%s + %s" % (answer[0], newAnswer[0])
        answers.extend(newAnswers)

if verbose_flag:
    print('======================================================================')

for answer in answers:
    try:
        answer.append(calculate_entropy(answer[1]))
    except:
        # this is basically disqualified
        answer.append(-10000)

sortedAnswers = sorted(answers, key=lambda my_answer: my_answer[2])
if print_all:
    print("All %d results, worst to best:" % len(sortedAnswers))
    for answer in sortedAnswers:
        print("%.2f <%s> %s" % (answer[2], answer[0], repr(answer[1])))
else:
    print("Top %d results, worst to best:" % numResults)
    for answer in sortedAnswers[len(sortedAnswers) - numResults + 1:]:
        print("%.2f <%s> %s" % (answer[2], answer[0], repr(answer[1])))
