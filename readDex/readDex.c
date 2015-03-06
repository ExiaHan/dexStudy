#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "dex.h"

int main(int argc, char *argv[])
{
  u1 *bFile;
  pDexHeader pdHeader;
  if (argc != 2){
	fprintf(stderr, "[I]: Usage %s [FILENAME]", argv[0]);
	return -1;
  }
  if (readDexFile(argv[1], &bFile) < 0){
	fprintf(stderr, "[E]: Error when Read Dex File %s\n", argv[1]);
	return -1;
  }
  pdHeader = (pDexHeader)bFile;

  //header
  if (readDexHeader(pdHeader) < 0){
	fprintf(stderr, "[E]: Error when Read Dex Header of File %s\n", argv[1]);
	return -2;
  }

  //string table
  if (pdHeader->string_ids_size != 0){
	printf("\n");
	readStringTable(pdHeader->string_ids_size, bFile, pdHeader->string_ids_off);
  }

  //type table
  if (pdHeader->type_ids_size != 0){
	printf("\n");
	readTypeTable(pdHeader->type_ids_size, bFile, pdHeader->type_ids_off, pdHeader->string_ids_off);
  }

  //proto table
  if (pdHeader->proto_ids_size != 0){
	printf("\n");
	readProtoTable(pdHeader->proto_ids_size, bFile, pdHeader->proto_ids_off, pdHeader->string_ids_off);
  }

  //Field table
  if (pdHeader->field_ids_size != 0) {
	printf("\n");
	readFieldTable(pdHeader->field_ids_size, bFile, pdHeader->field_ids_off);
  }

  //method table
  if (pdHeader->method_ids_size != 0) {
	printf("\n");
	readMethodTable(pdHeader->method_ids_size, bFile, pdHeader->method_ids_off);
  }

  //class def table
  if (pdHeader->class_def_size != 0) {
	printf("\n");
	readClassDefTable(pdHeader->class_def_size, bFile, pdHeader->class_def_off);
  }
  
  return 0;
}
