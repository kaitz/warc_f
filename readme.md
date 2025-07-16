Program for manipulating WARC [(Web ARChive)](https://en.wikipedia.org/wiki/WARC_(file_format))  files. 
Reordering, dumping and listing of its contents.

Expected header for WARC file is: WARC/1.0

# Command line options

* e|d

      e - Read a whole WARC file into memory and write out the WARC header followed by the content.
      WARC headers fields are swapped with id's (see table below).
  
      d - In decode mode the program reads in the WARC header and restors the original file. 
      Warning: Be sure that you have enough free memory (e option).
      This option creates only one output file.
* es|dm

      es - Split/dump mode. Read the WARC headers into memory and write out. 
      The WARC header content is written to files with file name corresponding to the record id in the file.
      File is written only when WARC CONTENT_LENGTH present and filled value is larger than 0.
      WARC headers fields are swapped with id's (see table below).
      This option creates multiple output files.
  
      dm - In decode mode the WARC header file is read into the memory.
      After that the output file is created by writing the header and reading/writing its corresponding content file if any.
* l{n}

      List WARC header record WARC_TYPE=="response" field values. Default is target-uri's (n=15) to output file.
      n can be value in the range of 0-26. (see table below)

# Memory usage
  * e,d - size of the file
  * es,dm,l - size of the WARC header size

# WARC field types and values
These field values are used internally. 
| ID  |  VALUE | 
| --- | --- | 
| WARC_TYPE |                      0| 
| WARC_RECORD_ID |                 1| 
| WARC_DATE |                      2| 
| CONTENT_LENGTH |                 3| 
| CONTENT_TYPE |                   4| 
| WARC_CONCURRENT_TO |             5| 
| WARC_BLOCK_DIGEST |              6| 
| WARC_PAYLOAD_DIGEST |            7| 
| WARC_IP_ADDRESS |                8| 
| WARC_REFERS_TO |                 9| 
| WARC_RESERVED1 |                 10| 
| WARC_REFERS_TO_TARGET_URI |      11| 
| WARC_REFERS_TO_DATE |            12| 
| WARC_RESERVED2 |                 13| 
| WARC_TARGET_URI |                14| 
| WARC_TRUNCATED |                 15| 
| WARC_WARCINFO_ID |               16| 
| WARC_FILENAME |                  17| 
| WARC_PROFILE |                   18| 
| WARC_IDENTIFIED_PAYLOAD_TYPE |   19| 
| WARC_SEGMENT_ORIGIN_ID |         20| 
| WARC_SEGMENT_NUMBER |            21| 
| WARC_SEGMENT_TOTAL_LENGTH |      22| 
| WARC_PROTOCOL |                  23| 
| WARC_CIPHER_SUITE |              24| 
| WARC_PAGE_ID |                   25| 
| WARC_JSON_METADATA|               26| 
| WARC_RESOURCE_TYPE|               27| 

WARC_RESERVED1 and WARC_RESERVED2 are '\r' and '\n' for easier parsing.
Some fields here are proposed and not final according to  [specifications](https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1/).  
I have seen files with header WARC/1.0 or WARC/1.1 containing proposed fields. It looks like a mess.

Error message "Unexpected field FIELD_NAME" is shown when the input file contains a field not shown in the above table.
FIELD_NAME is replaced with the actual field value in the file.
