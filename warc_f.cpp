/*  warc_f.cpp - WARC (Web ARChive) file content tool

    Copyright (C) 2025 Kaido Orav

    LICENSE

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; either version 2 of
    the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
    General Public License for more details at
    Visit <http://www.gnu.org/copyleft/gpl.html>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <algorithm>

namespace warcfile {

static const char CR=0x0d;
static const char LF=0x0a;

enum EnumLineTypes {
    LTYPE_NONE,LTYPE_LF,LTYPE_CRLF
};

enum WarcFields{
    WARC_TYPE,
    WARC_RECORD_ID,
    WARC_DATE,
    CONTENT_LENGTH,
    CONTENT_TYPE,
    WARC_CONCURRENT_TO,
    WARC_BLOCK_DIGEST,
    WARC_PAYLOAD_DIGEST,
    WARC_IP_ADDRESS,
    WARC_REFERS_TO,
    WARC_RESERVED1,
    WARC_REFERS_TO_TARGET_URI,
    WARC_REFERS_TO_DATE,
    WARC_RESERVED2,
    WARC_TARGET_URI,
    WARC_TRUNCATED,
    WARC_WARCINFO_ID,
    WARC_FILENAME,
    WARC_PROFILE,
    WARC_IDENTIFIED_PAYLOAD_TYPE,
    WARC_SEGMENT_ORIGIN_ID,
    WARC_SEGMENT_NUMBER,
    WARC_SEGMENT_TOTAL_LENGTH,
    WARC_PROTOCOL,      // proposed ?
    WARC_CIPHER_SUITE,  // proposed ?
    WARC_PAGE_ID,       // proposed ?
    WARC_JSON_METADATA,  // proposed ?
    WARC_RESOURCE_TYPE   // proposed ?
};

struct field {
    int id;
    std::string value;
};

static const std::vector<field> WARC_FIELDS={
    {WARC_TYPE , "WARC-Type"},
    {WARC_RECORD_ID , "WARC-Record-ID"},
    {WARC_DATE , "WARC-Date"},
    {CONTENT_LENGTH , "Content-Length"},
    {CONTENT_TYPE , "Content-Type"},
    {WARC_CONCURRENT_TO , "WARC-Concurrent-To"},
    {WARC_BLOCK_DIGEST , "WARC-Block-Digest"},
    {WARC_PAYLOAD_DIGEST , "WARC-Payload-Digest"},
    {WARC_IP_ADDRESS , "WARC-IP-Address"},
    {WARC_REFERS_TO , "WARC-Refers-To"},
    {WARC_RESERVED1 , "WARC_RESERVED1"},
    {WARC_REFERS_TO_TARGET_URI , "WARC-Refers-To-Target-URI"},
    {WARC_REFERS_TO_DATE , "WARC-Refers-To-Date"},
    {WARC_RESERVED2 , "WARC_RESERVED2"},
    {WARC_TARGET_URI , "WARC-Target-URI"},
    {WARC_TRUNCATED , "WARC-Truncated"},
    {WARC_WARCINFO_ID , "WARC-Warcinfo-ID"},
    {WARC_FILENAME , "WARC-Filename"},
    {WARC_PROFILE , "WARC-Profile"},
    {WARC_IDENTIFIED_PAYLOAD_TYPE , "WARC-Identified-Payload-Type"},
    {WARC_SEGMENT_ORIGIN_ID , "WARC-Segment-Origin-ID"},
    {WARC_SEGMENT_NUMBER , "WARC-Segment-Number"},
    {WARC_SEGMENT_TOTAL_LENGTH , "WARC-Segment-Total-Length"},
    {WARC_PROTOCOL , "WARC-Protocol"},
    {WARC_CIPHER_SUITE , "WARC-Cipher-Suite"},
    {WARC_PAGE_ID , "WARC-Page-ID"},
    {WARC_JSON_METADATA , "WARC-JSON-Metadata"},
    {WARC_RESOURCE_TYPE , "WARC-Resource-Type"}
};

int get_warc_field_id(std::string name) {
    for(int i=0; i < WARC_FIELDS.size(); i++) {
        if (WARC_FIELDS[i].value==name) return WARC_FIELDS[i].id;
    }
    return -1;
}
std::string get_warc_field_name(int id) {
    for(int i=0; i < WARC_FIELDS.size(); i++) {
        if (WARC_FIELDS[i].id==id) return WARC_FIELDS[i].value;
    }
    return "";
}

class Reader{
    private:
        std::string file_name;
        FILE *in;
        std::string line;
        EnumLineTypes linetype;
        std::string block;
        bool isEOF;
    public:
        explicit Reader(std::string filename): file_name(filename),isEOF(false) {
            in=fopen(file_name.c_str(),"rb");
            if (in==NULL) {
               printf("Input file not found.");
               exit(1);
            }
        };
        std::string const &ReadLine() {
            line="";
            linetype=LTYPE_NONE;
            int c=0;
            while ((c=getc(in))!=EOF) {
                line=line+char(c);
                if (c==CR) line.pop_back(),linetype=LTYPE_CRLF;
                else if (c==LF) {
                    if (linetype!=LTYPE_CRLF) linetype=LTYPE_LF;
                    line.pop_back();
                    break;
                }
            }
            isEOF=c==EOF;
            return line;
        }
        std::string const &ReadBlock(int size) {
            block="";
            block.resize(size);
            int len=fread(&block[0],1,size,in);
            if (len!=size) isEOF=true;
            block.resize(len);
            return block;
        }
        std::string const &LastLine() { return line; }
        EnumLineTypes const LineType() { return linetype; }
        bool End() { return isEOF; }
        void close() {fclose(in); }
        void seek(int len) {fseek(in, len, SEEK_CUR); }
};

class WarcField {
    public:
        std::string value;
        int id;
        WarcField() { };
};

class WarcRecord {
    public:
        std::string version;
        std::vector<WarcField> fields;
        std::string content;
        WarcRecord() { };
};

class WarcFile {
    private:
        Reader file;
        std::string outfile;
        std::vector<WarcRecord> records;
        bool doMergeSplit;
    public:
        WarcFile(std::string filename,std::string fileout,bool ms) : file(filename),outfile(fileout),doMergeSplit(ms) { };
        bool ReadRecord(bool doContent=true) {
            if (file.End()) {
                return false;
            }
            std::string line="";
            WarcRecord record;
            line=file.ReadLine();
            if (line=="WARC/1.0"){
                while (line=file.ReadLine(), line.size()>0 && file.End()==false) {
                    WarcField field;
                    auto p=std::find(line.begin(), line.end(), ':');
                    std::string fieldname;
                    std::move(line.begin(), p, std::back_inserter(fieldname));
                    int fieldID=get_warc_field_id(fieldname);
                    if (fieldID==-1) {
                       printf("Unexpected field %s\n", fieldname.c_str());
                       exit(1);
                    }
                    field.id=fieldID;
                    p++; // ':'
                    std::move(p, line.end(), std::back_inserter(field.value));
                    std::string field1=get_warc_field_name(field.id);
                    record.fields.push_back(field);
               }
            } else {
                return false;
            }
            int contentSize=0;

            for(auto j=0; j <record.fields.size(); j++) {
                if (record.fields[j].id==CONTENT_LENGTH) {
                    contentSize=std::stoi(record.fields[j].value);
                    break;
                }
            }
            // in list mode skip content reading and seek to next entry
            if (doContent==true) {
                std::string content=file.ReadBlock(contentSize);
                record.content=content;
                if (contentSize!=content.size()) {
                   printf("Content not same size %d %d\n", contentSize, content.size());
                }
            } else {
                file.seek(contentSize);
            }
            records.push_back(record);
            line=file.ReadLine();
            if (file.LineType()!=LTYPE_CRLF) printf("Line type wrong\n");
            line=file.ReadLine();
            if (file.LineType()!=LTYPE_CRLF) printf("Line type wrong\n");
            return true;
        }

        void EncodeWARC() {
            FILE *out=fopen(outfile.c_str(),"wb");
            //header
            for(auto i=0; i <records.size(); i++) {
                fprintf(out,"WARC/1.0\r\n");
                for(auto j=0; j <records[i].fields.size(); j++){ 
                    //std::string field=get_warc_field_name(records[i].fields[j].id);
                    putc(records[i].fields[j].id,out);//fwrite(&field[0],1,field.size(),out);
                    putc(':',out);
                    std::string value=records[i].fields[j].value;
                    fwrite(&value[0],1,records[i].fields[j].value.size(),out);
                    putc(CR,out);
                    putc(LF,out);
                }
                putc(CR,out);
                putc(LF,out);
                putc(CR,out);
                putc(LF,out);
            }
            putc(CR,out);
            putc(LF,out);
            // content
            for(auto i=0; i <records.size(); i++) {
                std::string content=records[i].content;
                if (doMergeSplit==false){
                    fwrite(&content[0],1,records[i].content.size(),out);
                } else {
                    std::string contentfile=std::to_string(i);
                    FILE *cfout=fopen(contentfile.c_str(), "wb");
                    fwrite(&content[0],1,records[i].content.size(),cfout);
                    fclose(cfout);
                }
            }
            fclose(out);
            file.close();
            printf("Records: %d\n ",records.size());
        }

        void DecodeWrite() {
            FILE *out=fopen(outfile.c_str(),"wb");
            for(auto i=0; i <records.size(); i++) {
                int contentSize=0;
                fprintf(out,"WARC/1.0\r\n");
                for(auto j=0; j <records[i].fields.size(); j++) {
                    if (records[i].fields[j].id==CONTENT_LENGTH) {
                       contentSize=std::stoi(records[i].fields[j].value);
                    }
                    std::string field=get_warc_field_name(records[i].fields[j].id);
                    fwrite(&field[0],1,field.size(),out);
                    putc(':',out);
                    std::string value=records[i].fields[j].value;
                    fwrite(&value[0],1,records[i].fields[j].value.size(),out);
                    putc(CR,out); putc(LF,out);
                }
                putc(CR,out); putc(LF,out);
                //content
                if (contentSize) {
                    std::string content;
                    if (doMergeSplit==false) {
                        content=file.ReadBlock(contentSize);
                    } else {
                        std::string contentfile=std::to_string(i);
                        content.resize(contentSize);
                        FILE *cfin=fopen(contentfile.c_str(), "rb");
                        int len=fread(&content[0],1,contentSize,cfin);
                        if (len!=contentSize) printf("File content mismatch. File %d\n", i);
                        fclose(cfin);
                    }
                    fwrite(&content[0],1,contentSize,out);
                }
                if (file.End()) {
                    break ;
                }
                putc(CR,out); putc(LF,out);
                putc(CR,out); putc(LF,out);
            }
        }

        bool DecodeWARC() {
            if (file.End()) {
                return false;
            }
            std::string line="";
            WarcRecord record;
            line=file.ReadLine();
            if (line=="WARC/1.0") {
                while (line=file.ReadLine(), line.size()>0 && file.End()==false) {
                    WarcField field;
                    auto p = std::find(line.begin(), line.end(), ':');
                    std::string fieldname;
                    std::move(line.begin(), p, std::back_inserter(fieldname));
                    int fieldID=line[0];//get_warc_field_id(fieldname);
                    if (fieldID==-1) {
                       printf("Unexpected field %s\n", fieldname.c_str());
                       exit(1);
                    }
                    field.id=fieldID;
                    p++; // ':'
                    std::move(p, line.end(), std::back_inserter(field.value));
                    record.fields.push_back(field);
                }
            } else {
                printf("Records: %d\n ", records.size());
                DecodeWrite();
                file.close();
                return false;
            }
            records.push_back(record);
            line=file.ReadLine();
            if (file.LineType()!=LTYPE_CRLF) printf("Line type wrong\n");
            return true;
        }

        void ListWARC(int field) {
            FILE *out=fopen(outfile.c_str(),"wb");
            for(auto i=0; i <records.size(); i++) {
                int fid=-1;
                int tid=-1;
                std::string value="";
                for(auto j=0; j <records[i].fields.size(); j++) {
                    if (fid==-1 && records[i].fields[j].id==WARC_TYPE && records[i].fields[j].value==" response") {
                        fid=records[i].fields[j].id; 
                    } if (tid==-1 && records[i].fields[j].id==field) {
                        tid=records[i].fields[j].id;
                        value=records[i].fields[j].value;
                    }
                }
                if (fid!=-1 && tid!=-1) {
                    if (value.size()>1)
                        fprintf(out,"%s\n",&value[1]); // skip first byte (space)
                }
             }
            fclose(out);
            printf("Records: %d\n ",records.size());
        }
};
}

using namespace warcfile;

int main(int argc, char **argv) {
    if (argc<4 || (argv[1][0]!='e' && argv[1][0]!='d' && argv[1][0]!='l')) {
        printf("warc_f v0.1 (C) 2025 Kaido Orav \nUsage: e[s]|d[m]|l input output\n"), exit(1);
    }
    bool mergesplit=false;
    if (argv[1][0]=='e' && argv[1][1]=='s') mergesplit=true;
    else if (argv[1][0]=='d' && argv[1][1]=='m') mergesplit=true;
    WarcFile file(argv[2],argv[3],mergesplit);

    if (argv[1][0]=='e') {
        // encoding
        while (file.ReadRecord());
        file.EncodeWARC();
    } else if (argv[1][0]=='d') {
        // decoding
        while (file.DecodeWARC());
    } else if (argv[1][0]=='l') {
        int field=WARC_TARGET_URI;
        if (argv[1][1]>='0' && argv[1][1]<='9') field=std::stoi(&argv[1][1]);
        if (field>WARC_RESOURCE_TYPE) field=WARC_TARGET_URI;
        // read WARC headers only
        while (file.ReadRecord(false));
        // list target uri
        file.ListWARC(field);
    }
    return 0;
}
