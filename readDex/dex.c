#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <string.h>
#include <ctype.h>
#include "dex.h"

static u4 NO_INDEX = 0xFFFFFFFF;

u4 AlignDex(u4 value, u4 uAlign)
{
  return (value + uAlign - 1) / uAlign * uAlign;
}

s4 decodeUleb128(u1 *pLeb128, pInfoUleb128 pInfoleb)
{

  u4 reslut = 0;
  u4 shift = 0;
  u4 size = 0;
  u1 ubyte;
  u1 *pTmpLeb = pLeb128;
  while(1){
	ubyte = *pTmpLeb;
	size += 1;
	reslut |= (ubyte & 0x7F) << shift;
	if ((ubyte & 0x80) == 0)
	  break;
	shift += 7;
	pTmpLeb ++;
  }
  pInfoleb->size = size;
  pInfoleb->value = reslut;
  return size;
}

u4 getFileSize(FILE *pDexFile)
{
  u4 uFileSize = 0;
  fseek(pDexFile, 0, SEEK_END);
  uFileSize = ftell(pDexFile);
  rewind(pDexFile);
  return uFileSize;
}

s4 readDexFile(char *pFileName, u1 **ppFile)
{
  FILE *pDexFile;
  u4 uFileSize;
  u1 *pcFile;
  char cValue;
  int reslut;
  if ((pDexFile = fopen(pFileName, "rb")) == NULL){
	fprintf(stderr, "[E]: Can't open File %s\n", pFileName);
	return -1;
  }
  if (!(uFileSize = getFileSize(pDexFile))){
	fprintf(stderr, "[E]: Can't get size of File %s\n", pFileName);
	return -2;
  }

  *ppFile = (u1 *)malloc(sizeof(u1) * uFileSize);
  pcFile = (u1 *)*ppFile;
  if (pcFile == NULL){
	fprintf(stderr, "[E]: Can't malloc memory to store File %s\n", pFileName);
	return -3;
  }
  
  reslut = fread(pcFile, sizeof(char), uFileSize, pDexFile);
  if (reslut != uFileSize){
	fprintf(stderr, "[E]: Error when read file to memory %s\n", pFileName);
	return -4;
  }

  fclose(pDexFile);
  return 0;
}


s4 readDexHeader(pDexHeader pHeader)
{
  pDexHeader pTmp = pHeader;
  printf("[I]: Dex Header Structure:\n");

  //start printf Header Info
  printf("\t|---Magic Number: ");
  for (int i = 0; i < sizeof(pTmp->magic); i++){
	if ('\n' == *(pTmp->magic + i))
	  printf("\\n\n");
	else
	  printf("%c", *(pTmp->magic + i));
  }
  printf("\t|---Version: %s\n", pTmp->version);
  printf("\t|---CheckSum: 0x%08X\n", pTmp->checkSum);
  printf("\t|---Signature[Hex]: ");
  for (int i = 0; i < sizeof(pTmp->signature); i++)
	printf("%02X", pTmp->signature[i]);
  printf("\n");
  printf("\t|---File Size: %u Byte[s]\n", pTmp->file_size);
  printf("\t|---Header Size: %u Byte[s]\n", pTmp->header_size);
  printf("\t|---Endian Tag: 0x%08X\n", pTmp->endian_tag);
  printf("\t|---Link Size: 0x%08X\n", pTmp->link_size);
  printf("\t|---Link Offset: 0x%08X\n", pTmp->link_off);
  printf("\t|---Map Off: 0x%08X\n", pTmp->map_off);
  printf("\t|---String IDs Size: 0x%08X\n", pTmp->string_ids_size);
  printf("\t|---String IDs Offset 0x%08X\n", pTmp->string_ids_off);
  printf("\t|---Type IDs Size 0x%08X\n", pTmp->type_ids_size);
  printf("\t|---Type IDs Offset 0x%08X\n", pTmp->type_ids_off);
  printf("\t|---Proto IDs Size 0x%08X\n", pTmp->proto_ids_size);
  printf("\t|---Proto IDs Offset 0x%08X\n", pTmp->proto_ids_off);
  printf("\t|---Field IDs Size 0x%08X\n", pTmp->field_ids_size);
  printf("\t|---Field IDs Offset 0x%08X\n", pTmp->field_ids_off);
  printf("\t|---Method IDs Size 0x%08X\n", pTmp->method_ids_size);
  printf("\t|---Method IDs Offset 0x%08X\n", pTmp->method_ids_off);
  printf("\t|---Class IDs Size 0x%08X\n", pTmp->class_def_size);
  printf("\t|---Class IDs Offset 0x%08X\n", pTmp->class_def_off);
  printf("\t|---Data Size 0x%08X\n", pTmp->data_size);
  printf("\t|---Data Offset 0x%08X\n", pTmp->data_off);

  return 0;
}

void displayString(u1* bFile, pDexStringId pStrIdItem)
{
  u1 *strData = bFile + pStrIdItem->stringDataOff;//point to data
  InfoUleb128 scInfoLeb128;//data value
  char *str;
  
  printf("\t|---String Data\n");
  decodeUleb128(strData, &scInfoLeb128);
  printf("\t|\t|---Size: %u\n", scInfoLeb128.value);
  str = (char *)(strData + scInfoLeb128.size);
  printf("\t|\t|---String: ");
  while(*str != '\0'){
	if(*str == '\n')
	  printf("\\n");
	else
	  printf("%c", *str);
	str++;
  }
  printf("\n");
  return;
}

s4 readStringTable(s4 num, u1 *bFile, u4 strIdOff)
{
  pDexStringId pStrIdItem = (pDexStringId)(bFile + strIdOff);//string table

  printf("[I]:Dex String Table:\n");
  for (int i = 0; i < num; i++, pStrIdItem++)
	displayString(bFile, pStrIdItem);
  
  return 0;
}

void displayType(u1 *bFile, pDexTypeId pTypeIdItem, pDexStringId pStrIdItem)
{
  u4 strOff = pTypeIdItem->descriptorIdx;
  u1 *strData = bFile + (pStrIdItem + strOff)->stringDataOff;//point to data
  InfoUleb128 scInfoLeb128;
  char *str;
  decodeUleb128(strData, &scInfoLeb128);
  str = (char *)(strData + scInfoLeb128.size);
  printf("\t|---Type: ");
  while (*str != '\0') {
	if (*str == '\n')
	  printf("\\n");
	else
	  printf("%c", *str);
	str++;
  }
  printf("\n");
  return;
}

s4 readTypeTable(s4 num, u1 *bFile, u4 typeIdOff, u4 strIdOff)
{
  pDexTypeId pTypeIdItem = (pDexTypeId)(bFile + typeIdOff);//type table
  pDexStringId pStrIdItem  = (pDexStringId)(bFile + strIdOff);
  printf("[I]:Dex Type Table:\n");
  for (int i = 0; i < num; i++, pTypeIdItem++)
	displayType(bFile, pTypeIdItem, pStrIdItem);

  return 0;
}

void disProtoShortDesc(u1* bFile, u4 shortyDescriptor, pDexStringId pStrIdItem)
{
  u4 strOff = (pStrIdItem + shortyDescriptor)->stringDataOff;
  u1 *strData = bFile + strOff;
  InfoUleb128 scInfoLeb128;
  char *str;
  decodeUleb128(strData, &scInfoLeb128);
  str = (char *)(strData + scInfoLeb128.size);
  printf("\t|\t|---Shorty Descriptor: ");
  while(*str != '\0'){
	if (*str == '\n')
	  printf("\\n");
	else
	  printf("%c", *str);
	str++;
  }
  printf("\n");
  return;
}

void disProtoReturnTy(u1 *bFile, u4 returnType)
{
  pDexHeader pHeader = (pDexHeader)bFile;
  pDexStringId pStrIdItem = (pDexStringId)(bFile + pHeader->string_ids_off);
  pDexTypeId pTypeIdItem = (pDexTypeId)(bFile + pHeader->type_ids_off);

  u4 strOff = (pTypeIdItem + returnType)->descriptorIdx;
  u1 *strData = bFile + (pStrIdItem + strOff)->stringDataOff;//point to data
  InfoUleb128 scInfoLeb128;
  char *str;
  decodeUleb128(strData, &scInfoLeb128);
  str = (char *)(strData + scInfoLeb128.size);
  printf("\t|\t|---Return Type: ");
  while (*str != '\0') {
	if (*str == '\n')
	  printf("\\n");
	else
	  printf("%c", *str);
	str++;
  }
  printf("\n");
  return;
}

void disProtoParams(u1 *bFile, u4 parameterOff)
{
  pDexHeader pHeader = (pDexHeader)bFile;
  pDexStringId pStrIdItem = (pDexStringId)(bFile + pHeader->string_ids_off);
  pDexTypeId pTypeIdItem = (pDexTypeId)(bFile + pHeader->type_ids_off);

  pDexTypeList pTypeList = (pDexTypeList)(bFile + parameterOff);
  pDexTypeItem pTypeItemElem = NULL;
  pDexTypeId pTypeIdItemTmp = NULL;
  u4 strOff = 0;
  u1 *strData = NULL;
  char *str = NULL;
  InfoUleb128 scInfoLeb128;
  
  printf("\t|\t|---Parameeter Type:\n");
  if (pTypeList->size == 0) {
	printf("\t|\t|\t|---NULL\n");
	return;
  }
  else {
	pTypeItemElem = pTypeList->list;
	for (int i = 0; i < (int)(pTypeList->size); i++, pTypeItemElem++){
	  pTypeIdItemTmp = pTypeIdItem + pTypeItemElem->typeIdx;
	  strOff = pTypeIdItemTmp->descriptorIdx;
	  strData = bFile + (pStrIdItem + strOff)->stringDataOff;
	  decodeUleb128(strData, &scInfoLeb128);
	  str = (char *)(strData + scInfoLeb128.size);
	  printf("\t|\t|\t|---");
	  while (*str != '\0') {
		if(*str == '\n')
		  printf("\\n");
		else
		  printf("%c", *str);
		str++;
	  }
	  printf("\n");
	}
  }
}

void displayProto(u1 *bFile, pDexProtoId pProtoIdItem, pDexStringId pStrIdItem)
{
  pDexHeader pHeader = (pDexHeader)bFile;
  pDexTypeId pTypeIdItem = (pDexTypeId)(bFile + pHeader->type_ids_off);
  
  u4 shortyDescriptor = pProtoIdItem->shortIdx;//index to string id
  u4 returnType = pProtoIdItem->returnTypeIdx;//index to type id
  u4 parameterOff = pProtoIdItem->parametersOff;//RVA to a type_list that descripe parameters

  printf("\t|---Proto Type:\n");
  disProtoShortDesc(bFile, shortyDescriptor, pStrIdItem);
  disProtoReturnTy(bFile,returnType);
  if (parameterOff)
	disProtoParams(bFile, parameterOff);
  else
	printf("\t|\t|---[No Parameter]\n");
  
  return;
}

s4 readProtoTable(s4 num, u1 *bFile, u4 protoIdOff, u4 strIdOff)
{
  pDexProtoId pProtoIdItem = (pDexProtoId)(bFile + protoIdOff);//proto table
  pDexStringId pStrIdItem = (pDexStringId)(bFile + strIdOff);
  printf("[I]:Dex Proto Table:\n");
  for(int i = 0; i < num; i++, pProtoIdItem++)
	displayProto(bFile, pProtoIdItem, pStrIdItem);

  return 0;
}

void disFieldClass(u1 *bFile, u2 classId, pDexStringId pStrIdItem, pDexTypeId pTypeIdItem)
{
  pDexStringId pStrIdItemTmp = pStrIdItem + (pTypeIdItem + classId)->descriptorIdx;
  InfoUleb128 scInfoLeb128;
  char *strData = (char *)(bFile + pStrIdItemTmp->stringDataOff);
  char *str = NULL;
  decodeUleb128(strData, &scInfoLeb128);
  str = strData + scInfoLeb128.size;
  printf("\t|\t|---Field Class :");
  while(*str != '\0'){
	if (*str == '\n')
	  printf("\\n");
	else
	  printf("%c", *str);
	str++;
  }
  printf("\n");
  return;
}

void disFieldType(u1 *bFile, u2 typeId, pDexStringId pStrIdItem, pDexTypeId pTypeIdItem)
{
  pDexStringId pStrIdItemTmp = pStrIdItem + (pTypeIdItem + typeId)->descriptorIdx;
  InfoUleb128 scInfoLeb128;
  char *strData = (char *)(bFile + pStrIdItemTmp->stringDataOff);
  char *str = NULL;
  decodeUleb128(strData, &scInfoLeb128);
  str = strData + scInfoLeb128.size;
  printf("\t|\t|---Field Type :");
  while(*str != '\0'){
	if (*str == '\n')
	  printf("\\n");
	else
	  printf("%c", *str);
	str++;
  }
  printf("\n");
  return;
}

void disFieldName(u1 *bFile, u4 nameId, pDexStringId pStrIdItem)
{
  pDexStringId pStrIdItemTmp = pStrIdItem + nameId;
  InfoUleb128 scInfoLeb128;
  char *strData = (char *)(bFile + pStrIdItemTmp->stringDataOff);
  char *str = NULL;
  decodeUleb128(strData, &scInfoLeb128);
  str = strData + scInfoLeb128.size;
  printf("\t|\t|---Field Name :");
  while(*str != '\0'){
	if (*str == '\n')
	  printf("\\n");
	else
	  printf("%c", *str);
	str++;
  }
  printf("\n");
  return;
}

void displayField(u1 *bFile, pDexFileId pFieldIdItem)
{
  pDexHeader pHeader = (pDexHeader)bFile;
  pDexStringId pStrIdItem = (pDexStringId)(bFile + pHeader->string_ids_off);
  pDexTypeId pTypeIdItem = (pDexTypeId)(bFile + pHeader->type_ids_off);

  printf("\t|---Field Info:\n");
  disFieldClass(bFile, pFieldIdItem->classIdx, pStrIdItem, pTypeIdItem);
  disFieldType(bFile, pFieldIdItem->typeIdx, pStrIdItem, pTypeIdItem);
  disFieldName(bFile, pFieldIdItem->nameIdx, pStrIdItem);
  
  return;
}

s4 readFieldTable(s4 num, u1 *bFile, u4 fieldOff)
{
  pDexHeader pHeader = (pDexHeader)bFile;
  pDexStringId pStrIdItem = (pDexStringId)(bFile + pHeader->string_ids_off);
  pDexTypeId pTypeIdItem = (pDexTypeId)(bFile + pHeader->type_ids_off);
  pDexFileId pFieldIdItem = (pDexFileId)(bFile + fieldOff);

  printf("[I]:Dex Field Table:\n");
  for(int i = 0; i < num; i++, pFieldIdItem++)
	displayField(bFile, pFieldIdItem);

  return 0;
}

void disMetProtoParams(u1 *bFile, u4 parameterOff)
{
  pDexHeader pHeader = (pDexHeader)bFile;
  pDexStringId pStrIdItem = (pDexStringId)(bFile + pHeader->string_ids_off);
  pDexTypeId pTypeIdItem = (pDexTypeId)(bFile + pHeader->type_ids_off);

  pDexTypeList pTypeList = (pDexTypeList)(bFile + parameterOff);
  pDexTypeItem pTypeItemElem = NULL;
  pDexTypeId pTypeIdItemTmp = NULL;
  u4 strOff = 0;
  u1 *strData = NULL;
  char *str = NULL;
  InfoUleb128 scInfoLeb128;
  
  printf("\t|\t|\t|---Parameeter Type:\n");
  if (pTypeList->size == 0) {
	printf("\t|\t|---NULL\n");
	return;
  }
  else {
	pTypeItemElem = pTypeList->list;
	for (int i = 0; i < (int)(pTypeList->size); i++, pTypeItemElem++){
	  pTypeIdItemTmp = pTypeIdItem + pTypeItemElem->typeIdx;
	  strOff = pTypeIdItemTmp->descriptorIdx;
	  strData = bFile + (pStrIdItem + strOff)->stringDataOff;
	  decodeUleb128(strData, &scInfoLeb128);
	  str = (char *)(strData + scInfoLeb128.size);
	  printf("\t|\t|\t|\t|---");
	  while (*str != '\0') {
		if(*str == '\n')
		  printf("\\n");
		else
		  printf("%c", *str);
		str++;
	  }
	  printf("\n");
	}
  }
}

void disMethodClass(u1 *bFile, u2 classId, pDexStringId pStrIdItem, pDexTypeId pTypeIdItem)
{
  pDexStringId pStrIdItemTmp = pStrIdItem + (pTypeIdItem + classId)->descriptorIdx;
  InfoUleb128 scInfoLeb128;
  char *strData = (char *)(bFile + pStrIdItemTmp->stringDataOff);
  char *str = NULL;
  decodeUleb128(strData, &scInfoLeb128);
  str = strData + scInfoLeb128.size;
  printf("\t|\t|---Method Class :");
  while(*str != '\0'){
	if (*str == '\n')
	  printf("\\n");
	else
	  printf("%c", *str);
	str++;
  }
  printf("\n");

  return;
}

void disMethodProto(u1 *bFile, u2 protoId, pDexStringId pStrIdItem, pDexTypeId pTypeIdItem, pDexProtoId pProtoIdItem)
{
  pDexProtoId pProtoIdItemTmp = pProtoIdItem + protoId;
  
  printf("\t|\t|---Proto Type:\n");

  printf("\t|");
  disProtoShortDesc(bFile, pProtoIdItemTmp->shortIdx, pStrIdItem);
  printf("\t|");
  disProtoReturnTy(bFile, pProtoIdItemTmp->returnTypeIdx);
  if (pProtoIdItemTmp->parametersOff)
	disMetProtoParams(bFile, pProtoIdItemTmp->parametersOff);
  else
	printf("\t|\t|\t|---[No Parameter]\n");
  
  return;
}
void disMethodName(u1 *bFile, u4 nameId, pDexStringId pStrIdItem)
{
  pDexStringId pStrIdItemTmp = pStrIdItem + nameId;
  InfoUleb128 scInfoLeb128;
  char *strData = (char *)(bFile + pStrIdItemTmp->stringDataOff);
  char *str = NULL;
  decodeUleb128(strData, &scInfoLeb128);
  str = strData + scInfoLeb128.size;
  printf("\t|\t|---Method Name :");
  while(*str != '\0'){
	if (*str == '\n')
	  printf("\\n");
	else
	  printf("%c", *str);
	str++;
  }
  printf("\n");
  
  return;
}

void displayMethod(u1 *bFile, pDexMethodId pMethodIdItem)
{
  pDexHeader pHeader = (pDexHeader)bFile;
  pDexStringId pStrIdItem = (pDexStringId)(bFile + pHeader->string_ids_off);
  pDexTypeId pTypeIdItem = (pDexTypeId)(bFile + pHeader->type_ids_off);
  pDexProtoId pProtoIdItem = (pDexProtoId)(bFile + pHeader->proto_ids_off);

  printf("\t|---Method Info:\n");
  disMethodClass(bFile, pMethodIdItem->classIdx, pStrIdItem, pTypeIdItem);
  disMethodProto(bFile, pMethodIdItem->protoIdx, pStrIdItem, pTypeIdItem, pProtoIdItem);
  disMethodName(bFile, pMethodIdItem->nameIdx, pStrIdItem);
  
  return;
}

s4 readMethodTable(s4 num, u1 *bFile, u4 methodOff)
{
  pDexHeader pHeader = (pDexHeader)bFile;
  pDexStringId pStrIdItem = (pDexStringId)(bFile + pHeader->string_ids_off);
  pDexTypeId pTypeIdItem = (pDexTypeId)(bFile + pHeader->type_ids_off);
  pDexMethodId pMethodIdItem = (pDexMethodId)(bFile + methodOff);

  printf("[I]:Dex Method Table:\n");
  for (int i = 0; i < num; i++, pMethodIdItem++)
	displayMethod(bFile, pMethodIdItem);
  
  return 0;
}

//classDefTable
void displayClassDef(u1 *bFile, pDexClassDef pClassDefItem)
{
  pDexHeader pHeader = (pDexHeader)bFile;
  pDexStringId pStrIdItem = (pDexStringId)(bFile + pHeader->string_ids_off);
  pDexTypeId pTypeIdItem = (pDexTypeId)(bFile + pHeader->type_ids_off);
  pDexMethodId pMethodIdItem = (pDexMethodId)(bFile + pHeader->method_ids_off);
  pDexFileId pFieldIdItem = (pDexFileId)(bFile + pHeader->field_ids_off);

  printf("\t|---Class Def Info:\n");
  disClsDefClass(bFile, pTypeIdItem, pStrIdItem, pClassDefItem->classIdx);
	printf("\t|\t|---Access Flags: 0x%08X\n", pClassDefItem->accessFlags);
	if (pClassDefItem->superClassIdx == NO_INDEX)
	  printf("\t|\t|---Super Class Info: NO Super Class\n");
	else
	  disClsDefSupCls(bFile, pTypeIdItem, pStrIdItem, pClassDefItem->superClassIdx);
	if (pClassDefItem->interfacesOff)
	  disClsDefIntfce(bFile, pTypeIdItem, pStrIdItem, pClassDefItem->interfacesOff);
	else
	  printf("\t|\t|---Interface Info: NO INTERFACE\n");
	if (pClassDefItem->sourceFileIdx == NO_INDEX)
	  printf("\t|\t|---NO INFO OF FILE\n");
	else
	  disClsDefSrc(bFile, pStrIdItem, pClassDefItem->sourceFileIdx);
	if (pClassDefItem->annotationsOff)
	  printf("\t|\t|---Have Annotations\n");
	else
	  printf("\t|\t|---No Annotations\n");
	if (pClassDefItem->classDataOff)
	  disClsDefClsData(bFile, pClassDefItem->classDataOff);
	else
	  printf("\t|\t|---NO Class DATA\n");
	if (pClassDefItem->staticValuesOff)
	  printf("\t|\t|---Have Static Value\n");
	else
	  printf("\t|\t|---NO Static Value\n");

	return;
 }
void disClsDefClass(u1 *bFile, pDexTypeId pTypeIdItem, pDexStringId pStrIdItem, u4 classOff)
{
  pDexTypeId pTypeIdItemTmp = pTypeIdItem + classOff;
  pDexStringId pStrIdItemTmp = pStrIdItem + pTypeIdItemTmp->descriptorIdx;
  InfoUleb128 scInfoLeb128;
  char *strData = (char *)(bFile + pStrIdItemTmp->stringDataOff);
  char *str = NULL;
  decodeUleb128(strData, &scInfoLeb128);
  str = strData + scInfoLeb128.size;

  printf("\t|\t|---Class Info: ");
  while (*str != '\0') {
	if (*str == '\n')
	  printf("\\n");
	else
	  printf("%c", *str);
	str++;
  }
  printf("\n");
  return;
}

void disClsDefSupCls(u1 *bFile, pDexTypeId pTypeIdItem, pDexStringId pStrIdItem, u4 superClsOff)
{
  pDexTypeId pTypeIdItemTmp = pTypeIdItem + superClsOff;
  pDexStringId pStrIdItemTmp = pStrIdItem + pTypeIdItemTmp->descriptorIdx;
  InfoUleb128 scInfoLeb128;
  char *strData = (char *)(bFile + pStrIdItemTmp->stringDataOff);
  char *str = NULL;
  decodeUleb128(strData, &scInfoLeb128);
  str = strData + scInfoLeb128.size;

  printf("\t|\t|---Super Class Info: ");
  while (*str != '\0') {
	if (*str == '\n')
	  printf("\\n");
	else
	  printf("%c", *str);
	str++;
  }
  printf("\n");
  return;
}

void disClsDefIntfce(u1 *bFile, pDexTypeId pTypeIdItem, pDexStringId pStrIdItem, u4 interfceOff)
{
  pDexTypeList pTypeListItem = (pDexTypeList)(bFile + interfceOff);
  pDexTypeId pTypeIdItemTmp;
  pDexTypeItem pTypeItemElm;
  pDexStringId pStrIdItemTmp;
  InfoUleb128 scInfoLeb128;
  char *strData = NULL;
  char *str = NULL;

  printf("\t|\t|---Interface Info: \n");
  if (pTypeListItem->size == 0)
	printf("\t|\t|\t|---Type List NULL\n");
  else {
	pTypeItemElm = pTypeListItem->list;
	for (int i = 0; i < pTypeListItem->size; i++, pTypeItemElm++){
	  pTypeIdItemTmp = pTypeIdItem + pTypeItemElm->typeIdx;
	  pStrIdItemTmp = pStrIdItem + pTypeIdItemTmp->descriptorIdx;
	  strData = (char *)(bFile + pStrIdItemTmp->stringDataOff);
	  decodeUleb128(strData, &scInfoLeb128);
	  str = strData + scInfoLeb128.size;
	  printf("\t|\t|\t|---Type List Info:");
	  while (*str != '\0') {
		if (*str == '\n')
		  printf("\\n");
		else
		  printf("%c", *str);
		str++;
	  }
	  printf("\n");
	}
  }  
  return;
}

void disClsDefSrc(u1 *bFile, pDexStringId pStrIdItem, u4 sourceFileId)
{
  pDexStringId pStrIdItemTmp = pStrIdItem + sourceFileId;
  InfoUleb128 scInfoLeb128;
  char *strData = (char *)(bFile + pStrIdItemTmp->stringDataOff);
  char *str = NULL;
  decodeUleb128(strData, &scInfoLeb128);
  str = strData + scInfoLeb128.size;
  printf("\t|\t|---Source File Info: ");
  while(*str != '\0'){
	if (*str == '\n')
	  printf("\\n");
	else
	  printf("%c", *str);
	str++;
  }
  printf("\n");
  
  return;

}

void disClsDefClsData(u1 *bFile, u4 classDataOff)
{
  pDexHeader pHeader = (pDexHeader)bFile;
  pDexStringId pStrIdItem = (pDexStringId)(bFile + pHeader->string_ids_off);
  pDexTypeId pTypeIdItem = (pDexTypeId)(bFile + pHeader->type_ids_off);
  pDexFileId pFieldIdItem = (pDexFileId)(bFile + pHeader->field_ids_off);
  pDexFileId pFieldIdItemTmp;
  pDexMethodId pMethodIdItem = (pDexMethodId)(bFile + pHeader->method_ids_off);
  pDexClassData pClassDataItem = (pDexClassData)(bFile + classDataOff);
  u1 *startOfClassDataItem = bFile + classDataOff;//for uleb128
  u1 *uleb128Tmp = startOfClassDataItem;
  u1 *fieldStart, *methodStart;
  u4 xFieldSize[4];
  u4 fieldId, methodId, accessFlag, codeOff;  
  InfoUleb128 scInfoLeb128;
  char strxField[4][20] = {"Static Field", "Instance Field", "Direct Method", "Virtual Method"};  
  
  printf("\t|\t|---Class Data:\n");
  for (int i = 0; i < 4; i++) {
	decodeUleb128(uleb128Tmp, &scInfoLeb128);
	xFieldSize[i] = scInfoLeb128.value;
	uleb128Tmp += scInfoLeb128.size;
  }
  fieldStart = uleb128Tmp;
  for (int k = 0; k < 2; k++) {
	if (xFieldSize[k] == 0) {
	  printf("\t|\t|\t|---%s: NULL\n",(strxField + k));
	  continue;
	}
	else {
	  for (int i = 0; i < xFieldSize[k]; i++) {
		decodeUleb128(fieldStart, &scInfoLeb128);
		fieldId = scInfoLeb128.value;
		fieldStart += scInfoLeb128.size;
		decodeUleb128(fieldStart, &scInfoLeb128);
		accessFlag = scInfoLeb128.value;
		fieldStart += scInfoLeb128.size;
		pFieldIdItemTmp = pFieldIdItem + fieldId;
		printf("\t|\t|\t|---%s:\n", (strxField + k));
		printf("\t|\t|\t|\t|---Field Info:\n");
		printf("\t|\t|\t|");
		disFieldClass(bFile, pFieldIdItemTmp->classIdx, pStrIdItem, pTypeIdItem);
		printf("\t|\t|\t|");
		disFieldType(bFile, pFieldIdItemTmp->typeIdx, pStrIdItem, pTypeIdItem);
		printf("\t|\t|\t|");
		disFieldName(bFile, pFieldIdItemTmp->nameIdx, pStrIdItem);
		printf("\t|\t|\t|\t|---Access Flag: 0x08%X\n", accessFlag);
		
	  }
	}
  }
  methodStart = fieldStart;
  for (int k = 2; k < 4; k++) {
	if (xFieldSize[k] == 0) {
	  printf("\t|\t|\t|---%s: NULL\n",(strxField + k));
	  continue;
	}
	else {
	  for (int i = 0; i < xFieldSize[k]; i++) {
		decodeUleb128(methodStart, &scInfoLeb128);
		methodId = scInfoLeb128.value;
		methodStart += scInfoLeb128.size;
		decodeUleb128(methodStart, &scInfoLeb128);
		accessFlag = scInfoLeb128.value;
		methodStart += scInfoLeb128.size;
		decodeUleb128(methodStart, &scInfoLeb128);
		codeOff = scInfoLeb128.value;
		methodStart += scInfoLeb128.size;
		pFieldIdItemTmp = pFieldIdItem + fieldId;
		printf("\t|\t|\t|---%s:\n", (strxField + k));
		
		printf("\t|\t|\t|\t|---Field Info:\n");
		printf("\t|\t|\t|");
		disFieldClass(bFile, pFieldIdItemTmp->classIdx, pStrIdItem, pTypeIdItem);
		printf("\t|\t|\t|");
		disFieldType(bFile, pFieldIdItemTmp->typeIdx, pStrIdItem, pTypeIdItem);
		printf("\t|\t|\t|");
		disFieldName(bFile, pFieldIdItemTmp->nameIdx, pStrIdItem);
		printf("\t|\t|\t|\t|---Access Flag: 0x08%X\n", accessFlag);

		if (codeOff)
		  disClsDataCode(bFile, codeOff);
		else
		  printf("\t|\t|\t|\t|---Code Info: Abstract or Native\n");
	  }
	}
  }
  return;
}

void disClsDataCode(u1 *bFile, u4 codeOff)
{
  pDexCode pCodeItem = (pDexCode)(bFile + codeOff);
  u2 *code;
  printf("\t|\t|\t|\t|---Code Info:\n");
  printf("\t|\t|\t|\t|\t|---Register Size: %u\n", pCodeItem->resgisterSize);
  printf("\t|\t|\t|\t|\t|---Ins Size: %u\n", pCodeItem->insSize);
  printf("\t|\t|\t|\t|\t|---Outs Size: %u\n", pCodeItem->outsSize);
  printf("\t|\t|\t|\t|\t|---Tries Size: %u\n", pCodeItem->triesSize);
  if (pCodeItem->debugInfoOff)
	printf("\t|\t|\t|\t|\t|---Debug Info Off: %u\n", pCodeItem->debugInfoOff);
  else
	printf("\t|\t|\t|\t|\t|---Debug Info: NULL\n");
  printf("\t|\t|\t|\t|\t|---Instruction Size: %u\n", pCodeItem->insnsSize);
  printf("\t|\t|\t|\t|\t|---Instruction OpCode: ");
  code = pCodeItem->Insns;
  for (u4 i = 0; i < pCodeItem->insnsSize; i++, code++)
	printf("0x%04X ", (u4)*code);
  printf("\n");
  return;
}
s4 readClassDefTable(s4 num, u1 *bFile, u4 ClassDefOff)
{
  pDexClassDef pClassDefItem = (pDexClassDef)(bFile + ClassDefOff);
  
  printf("[I]:Dex Class Define Table:\n");
  for (int i = 0; i < num; i++, pClassDefItem++)
	displayClassDef(bFile, pClassDefItem);

  return 0;
}









