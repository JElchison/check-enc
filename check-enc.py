#!/usr/bin/python

# Name:  checkenc.py
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

import binascii
import sys
import codecs
import base64
import math
import copy
import yenc


# default number of results to display
numResults = 20

# create table of frequency logarithms
logs = dict()
logs[ 'a' ] = math.log( 0.11602, 2 )
logs[ 'b' ] = math.log( 0.04702, 2 )
logs[ 'c' ] = math.log( 0.03511, 2 )
logs[ 'd' ] = math.log( 0.02670, 2 )
logs[ 'e' ] = math.log( 0.02000, 2 )
logs[ 'f' ] = math.log( 0.03779, 2 )
logs[ 'g' ] = math.log( 0.01950, 2 )
logs[ 'h' ] = math.log( 0.07232, 2 )
logs[ 'i' ] = math.log( 0.06286, 2 )
logs[ 'j' ] = math.log( 0.00631, 2 )
logs[ 'k' ] = math.log( 0.00690, 2 )
logs[ 'l' ] = math.log( 0.02705, 2 )
logs[ 'm' ] = math.log( 0.04374, 2 )
logs[ 'n' ] = math.log( 0.02365, 2 )
logs[ 'o' ] = math.log( 0.06264, 2 )
logs[ 'p' ] = math.log( 0.02545, 2 )
logs[ 'q' ] = math.log( 0.00173, 2 )
logs[ 'r' ] = math.log( 0.01653, 2 )
logs[ 's' ] = math.log( 0.07755, 2 )
logs[ 't' ] = math.log( 0.16671, 2 )
logs[ 'u' ] = math.log( 0.01487, 2 )
logs[ 'v' ] = math.log( 0.00619, 2 )
logs[ 'w' ] = math.log( 0.06661, 2 )
logs[ 'x' ] = math.log( 0.00005, 2 )
logs[ 'y' ] = math.log( 0.01620, 2 )
logs[ 'z' ] = math.log( 0.00050, 2 )


def PrintHelp():
    print """
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
    """ % numResults    


def CalculateEntropy( data ):
    score = 0
    for char in data:
        try:
            score += logs[ char.lower() ]
        except:
            # not a character.  subtract arbitrary amount from score.
            score -= 100
    return score


def ParseData( inData, bDecode, bCaesar ):
    answers = list()
    
    if bDecode is True:
        
        for name in ( 'hex_codec', 'base64_codec', 'rot_13', 'utf_8', 'utf_16_be', 'utf_16_le', 'bz2', 'zip', 'idna', 'palmos', 'punycode', 'quopri_codec', 'utf_7' ):
            try:
                result = inData.decode( name )
                if bVerbose:
                    print "%s succeeded" % name
                answers.append( [ name, repr( result ) ] )
            except Exception as ex:
                if bVerbose:
                    print "%s FAILED: %s" % ( name, ex )
    
        try:
            name = 'base32'
            result = base64.b32decode( inData )
            if bVerbose:
                print "%s succeeded" % name
            answers.append( [ name, repr( result ) ] )
        except Exception as ex:
            if bVerbose:
                print "%s FAILED: %s" % ( name, ex )
    
        try:
            name = 'uuencode'
            result = binascii.a2b_uu( inData )
            if bVerbose:
                print "%s succeeded" % name
            answers.append( [ name, repr( result ) ] )
        except Exception as ex:
            if bVerbose:
                print "%s FAILED: %s" % ( name, ex )
            
        try:
            name = 'quotable'
            result = binascii.a2b_qp( inData )
            if bVerbose:
                print "%s succeeded" % name
            answers.append( [ name, repr( result ) ] )
        except Exception as ex:
            if bVerbose:
                print "%s FAILED: %s" % ( name, ex )
            
        try:
            name = 'binhex4'
            result = binascii.rledecode_hqx( binascii.a2b_hqx( inData ) )
            if bVerbose:
                print "%s succeeded" % name
            answers.append( [ name, repr( result ) ] )
        except Exception as ex:
            if bVerbose:
                print "%s FAILED: %s" % ( name, ex )
        
        try:
            name = 'yenc'
            decoder = yenc.Decoder()
            decoder.feed( inData )
            result = decoder.getDecoded() 
            if bVerbose:
                print "%s succeeded" % name
            answers.append( [ name, repr( result ) ] )
        except Exception as ex:
            if bVerbose:
                print "%s FAILED: %s" % ( name, ex )

    else:
        
        for name in ( 'hex_codec', 'base64_codec', 'rot_13', 'utf_8', 'utf_16_be', 'utf_16_le', 'bz2', 'zip', 'idna', 'palmos', 'punycode', 'quopri_codec', 'utf_7' ):
            try:
                result = inData.encode( name )
                if bVerbose:
                    print "%s succeeded" % name
                answers.append( [ name, repr( result ) ] )
            except Exception as ex:
                if bVerbose:
                    print "%s FAILED: %s" % ( name, ex )
    
        try:
            name = 'base32'
            result = base64.b32encode( inData )
            if bVerbose:
                print "%s succeeded" % name
            answers.append( [ name, repr( result ) ] )
        except Exception as ex:
            if bVerbose:
                print "%s FAILED: %s" % ( name, ex )
    
        try:
            name = 'uuencode'
            result = binascii.b2a_uu( inData )
            if bVerbose:
                print "%s succeeded" % name
            answers.append( [ name, repr( result ) ] )
        except Exception as ex:
            if bVerbose:
                print "%s FAILED: %s" % ( name, ex )
            
        try:
            name = 'quotable'
            result = binascii.b2a_qp( inData )
            if bVerbose:
                print "%s succeeded" % name
            answers.append( [ name, repr( result ) ] )
        except Exception as ex:
            if bVerbose:
                print "%s FAILED: %s" % ( name, ex )
            
        try:
            name = 'binhex4'
            result = binascii.b2a_hqx( binascii.rlecode_hqx( inData ) )
            if bVerbose:
                print "%s succeeded" % name
            answers.append( [ name, repr( result ) ] )
        except Exception as ex:
            if bVerbose:
                print "%s FAILED: %s" % ( name, ex )
        
        try:
            name = 'yenc'
            encoder = yenc.Encoder()
            encoder.feed( inData )
            result = encoder.getEncoded() 
            if bVerbose:
                print "%s succeeded" % name
            answers.append( [ name, repr( result ) ] )
        except Exception as ex:
            if bVerbose:
                print "%s FAILED: %s" % ( name, ex )

    if bCaesar:
        for i in range( 1, 256 ):
            answers.append( [ "Caesar_%d" % i, repr( ''.join( [ chr( ( ord( c ) + i ) % 256 ) for c in inData ] ) ) ] )
        
    return answers


# initialize parameters
bDecode = True
bVerbose = False
isFile = False
twoPasses = True
printAll = False
inData = ''
inFile = ''


if len( sys.argv ) == 1:
    PrintHelp()
    exit()

for arg in sys.argv[ 1 : ]:
    if arg == '-e':
        bDecode = False
    elif arg == '-d':
        bDecode = True
    elif arg == '-v':
        bVerbose = True
    elif arg == '-f':
        isFile = True
    elif arg == '-1':
        twoPasses = False
    elif arg == '-a':
        printAll = True
    elif arg == '-h':
        PrintHelp()
        exit()
    else:
        if isFile:
            inFilename = arg
        else:
            inData = arg

if isFile is True:
    inFile = open( inFilename, 'r' )
    inData = inFile.read()
    inFile.close()
    
# do operation
answers = ParseData( inData, bDecode, True )

if twoPasses:
    print "First pass complete.  Now trying permutating each result..."
    # try "2-dimensional" operation (perform ParseData() on each answer)
    answers_orig = copy.copy( answers )
    for answer in answers_orig:
        # only do Caesar once
        if ( answer[ 0 ].find( 'Caesar' ) == -1 ):
            newAnswers = ParseData( answer[ 1 ], bDecode, True )
        else:
            newAnswers = ParseData( answer[ 1 ], bDecode, False )
        for newAnswer in newAnswers:
            newAnswer[ 0 ] = "%s + %s" % ( answer[ 0 ], newAnswer[ 0 ] )
        answers.extend( newAnswers )

if bVerbose:
    print '======================================================================'

for answer in answers:
    try:
        answer.append( CalculateEntropy( answer[ 1 ] ) )
    except:
        # this is basically disqualified
        answer.append( -10000 )
    
sortedAnswers = sorted( answers, key=lambda answer: answer[ 2 ] )
if printAll:
    print "All %d results, worst to best:" % len( sortedAnswers )
    for answer in sortedAnswers:
        print "%.2f <%s> %s" % ( answer[ 2 ], answer[ 0 ], answer[ 1 ] )
else:        
    print "Top %d results, worst to best:" % numResults
    for answer in sortedAnswers[ len( sortedAnswers ) - numResults + 1 : ]:
        print "%.2f <%s> %s" % ( answer[ 2 ], answer[ 0 ], answer[ 1 ] )
