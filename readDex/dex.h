#ifndef _DEX_H_
#define _DEX_H_

#include <stdint.h>
#include <stdbool.h>

typedef uint8_t u1;
typedef uint16_t u2;
typedef uint32_t u4;
typedef uint64_t u8;
typedef int8_t s1;
typedef int16_t s2;
typedef int32_t s4;
typedef int64_t s8;

//value format
enum ValueFormat {
  VALUE_BYTE = 0x00,
  VALUE_SHORT = 0x02,
  VALUE_CHAR = 0x03,
  VALUE_INT = 0x04,
  VALUE_LONG = 0x06,
  VALUE_FLOAT = 0x10,
  VALUE_DOUBLE = 0x11,
  VALUE_STRING = 0x17,
  VALUE_TYPE = 0x18,
  VALUE_FIELD = 0x19,
  VALUE_METHOD = 0x1a,
  VALUE_ENUM = 0x1b,
  VALUE_ARRAY = 0x1c,
  VALUE_ANNOTATION = 0x1d,
  VALUE_NULL = 0x1e,
  VALUE_BOOLEAN = 0x1f,
};

//Enumeration of all the primitive types.
enum PrimitiveType {
    PRIM_NOT        = 0,       /* value is a reference type, not a primitive type */
    PRIM_VOID       = 1,
    PRIM_BOOLEAN    = 2,
    PRIM_BYTE       = 3,
    PRIM_SHORT      = 4,
    PRIM_CHAR       = 5,
    PRIM_INT        = 6,
    PRIM_LONG       = 7,
    PRIM_FLOAT      = 8,
    PRIM_DOUBLE     = 9,
};



//access flags
enum AccessFlag{
    ACC_PUBLIC       = 0x00000001,       // class, field, method, ic
    ACC_PRIVATE      = 0x00000002,       // field, method, ic
    ACC_PROTECTED    = 0x00000004,       // field, method, ic
    ACC_STATIC       = 0x00000008,       // field, method, ic
    ACC_FINAL        = 0x00000010,       // class, field, method, ic
    ACC_SYNCHRONIZED = 0x00000020,       // method (only allowed on natives)
    ACC_SUPER        = 0x00000020,       // class (not used in Dalvik)
    ACC_VOLATILE     = 0x00000040,       // field
    ACC_BRIDGE       = 0x00000040,       // method (1.5)
    ACC_TRANSIENT    = 0x00000080,       // field
    ACC_VARARGS      = 0x00000080,       // method (1.5)
    ACC_NATIVE       = 0x00000100,       // method
    ACC_INTERFACE    = 0x00000200,       // class, ic
    ACC_ABSTRACT     = 0x00000400,       // class, method, ic
    ACC_STRICT       = 0x00000800,       // method
    ACC_SYNTHETIC    = 0x00001000,       // field, method, ic
    ACC_ANNOTATION   = 0x00002000,       // class, ic (1.5)
    ACC_ENUM         = 0x00004000,       // class, field, ic (1.5)
    ACC_CONSTRUCTOR  = 0x00010000,       // method (Dalvik only)
    ACC_DECLARED_SYNCHRONIZED =
                       0x00020000,       // method (Dalvik only)
    ACC_CLASS_MASK =
        (ACC_PUBLIC | ACC_FINAL | ACC_INTERFACE | ACC_ABSTRACT
                | ACC_SYNTHETIC | ACC_ANNOTATION | ACC_ENUM),
    ACC_INNER_CLASS_MASK =
        (ACC_CLASS_MASK | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC),
    ACC_FIELD_MASK =
        (ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC | ACC_FINAL
                | ACC_VOLATILE | ACC_TRANSIENT | ACC_SYNTHETIC | ACC_ENUM),
    ACC_METHOD_MASK =
        (ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC | ACC_FINAL
                | ACC_SYNCHRONIZED | ACC_BRIDGE | ACC_VARARGS | ACC_NATIVE
                | ACC_ABSTRACT | ACC_STRICT | ACC_SYNTHETIC | ACC_CONSTRUCTOR
                | ACC_DECLARED_SYNCHRONIZED),
};

//char str[][6] = {" "," "," "," "," "," "};

//

/* annotation constants */
enum {
    kDexVisibilityBuild         = 0x00,     /* annotation visibility */
    kDexVisibilityRuntime       = 0x01,
    kDexVisibilitySystem        = 0x02,

    kDexAnnotationByte          = 0x00,
    kDexAnnotationShort         = 0x02,
    kDexAnnotationChar          = 0x03,
    kDexAnnotationInt           = 0x04,
    kDexAnnotationLong          = 0x06,
    kDexAnnotationFloat         = 0x10,
    kDexAnnotationDouble        = 0x11,
    kDexAnnotationString        = 0x17,
    kDexAnnotationType          = 0x18,
    kDexAnnotationField         = 0x19,
    kDexAnnotationMethod        = 0x1a,
    kDexAnnotationEnum          = 0x1b,
    kDexAnnotationArray         = 0x1c,
    kDexAnnotationAnnotation    = 0x1d,
    kDexAnnotationNull          = 0x1e,
    kDexAnnotationBoolean       = 0x1f,

    kDexAnnotationValueTypeMask = 0x1f,     /* low 5 bits */
    kDexAnnotationValueArgShift = 5,
};

/* map item type codes */
enum {
    kDexTypeHeaderItem               = 0x0000,
    kDexTypeStringIdItem             = 0x0001,
    kDexTypeTypeIdItem               = 0x0002,
    kDexTypeProtoIdItem              = 0x0003,
    kDexTypeFieldIdItem              = 0x0004,
    kDexTypeMethodIdItem             = 0x0005,
    kDexTypeClassDefItem             = 0x0006,
    kDexTypeMapList                  = 0x1000,
    kDexTypeTypeList                 = 0x1001,
    kDexTypeAnnotationSetRefList     = 0x1002,
    kDexTypeAnnotationSetItem        = 0x1003,
    kDexTypeClassDataItem            = 0x2000,
    kDexTypeCodeItem                 = 0x2001,
    kDexTypeStringDataItem           = 0x2002,
    kDexTypeDebugInfoItem            = 0x2003,
    kDexTypeAnnotationItem           = 0x2004,
    kDexTypeEncodedArrayItem         = 0x2005,
    kDexTypeAnnotationsDirectoryItem = 0x2006,
};

/* auxillary data section chunk codes */
enum {
    kDexChunkClassLookup            = 0x434c4b50,   /* CLKP */
    kDexChunkRegisterMaps           = 0x524d4150,   /* RMAP */

    kDexChunkEnd                    = 0x41454e44,   /* AEND */
};

/* debug info opcodes and constants */
enum {
    DBG_END_SEQUENCE         = 0x00,
    DBG_ADVANCE_PC           = 0x01,
    DBG_ADVANCE_LINE         = 0x02,
    DBG_START_LOCAL          = 0x03,
    DBG_START_LOCAL_EXTENDED = 0x04,
    DBG_END_LOCAL            = 0x05,
    DBG_RESTART_LOCAL        = 0x06,
    DBG_SET_PROLOGUE_END     = 0x07,
    DBG_SET_EPILOGUE_BEGIN   = 0x08,
    DBG_SET_FILE             = 0x09,
    DBG_FIRST_SPECIAL        = 0x0a,
    DBG_LINE_BASE            = -4,
    DBG_LINE_RANGE           = 15,
};


//dex header
typedef struct dexHeader{
  /******************************************************
   *Caution all the RVA relative to dex file beginning,
   *and the RVA will be 0x0 if the boundle value's size
   *is 0x0
   *****************************************************/
  u1 magic[4];//"dex\n"
  u1 version[4];//"035\0"or"036\0"
  u4 checkSum;//check range:behind this value
  u1 signature[20];//check range:behind this value, and it's the dex that haven't been optimized
  u4 file_size;//byte size of file
  u4 header_size;//current version it should 0x70
  u4 endian_tag;//big endian or little endian
  u4 link_size;//number of dynamic link library
  u4 link_off;//RVA, Relative Virtual Address of File start
  u4 map_off;//RVA ,Map Section
  u4 string_ids_size;//number of String
  u4 string_ids_off;//RVA
  u4 type_ids_size;//number of element in TypeIDs List
  u4 type_ids_off;//RVA
  u4 proto_ids_size;//number of element in ProtoTypeIDs List
  u4 proto_ids_off;//RVA
  u4 field_ids_size;//number of element in FieldIDs List
  u4 field_ids_off;//RVA
  u4 method_ids_size;//number of element in MethodIDs List
  u4 method_ids_off;//RVA
  u4 class_def_size;//
  u4 class_def_off;//RVA
  u4 data_size;//size of DataSection, 4 bytes align
  u4 data_off;//RVA
}DexHeader, *pDexHeader;

//Map_Item
typedef struct dexMapItem
{
  u2 type;
  u2 unused;
  u4 size;
  u4 offset;
}DexMapItem, *pDexMapItem;

//Map_List
typedef struct dexMapList
{
  u4 size;
  DexMapItem list[1];
}DexMapList, *pDexMapList;

//string_id_item
typedef struct dexStringId
{
  u4 stringDataOff;
}DexStringId, *pDexStringId;

//string_data_item
//uleb128 is variable data type ,from 1 byte to 3bytes.
typedef struct dexStringDataItemn
{
  u1 *uleb128;
  u1 *str;
}DexStringDataItem, *pDexStringDataItem;

//type_id_item
typedef struct dexTypeId{
  u4 descriptorIdx;
}DexTypeId, *pDexTypeId;

//field_id_item
typedef struct dexFieldId
{
  u2 classIdx;
  u2 typeIdx;
  u4 nameIdx;
}DexFileId, *pDexFileId;

//method_id_item
typedef struct dexMethodId
{
  u2 classIdx;
  u2 protoIdx;
  u4 nameIdx;
}DexMethodId, *pDexMethodId;

//proto_id_item
typedef struct dexProtoId
{
  u4 shortIdx;
  u4 returnTypeIdx;
  u4 parametersOff;
}DexProtoId, *pDexProtoId;

//class_dex_item
typedef struct dexClassDef
{
  u4 classIdx;
  u4 accessFlags;
  u4 superClassIdx;
  u4 interfacesOff;
  u4 sourceFileIdx;
  u4 annotationsOff;
  u4 classDataOff;
  u4 staticValuesOff;
}DexClassDef, *pDexClassDef;

//encoded_field
typedef struct dexEncodeField
{
  //all is uLeb128
  u1 *field_idx_diff;
  u1 *access_flags;
}DexEncodedField, *pDexEncodedField;

//encoded_method
typedef struct dexEncodedMethod
{
  //all is uLeb128
  u1 *method_idx_diff;
  u1 *access_flags;
  u1 *code_off;
}DexEncodedMethod, *pDexEncodedMethod;

//class_dex_data
typedef  struct dexClassData
{
  //below size is uLeb128
  u1 *staticFieldSize;
  u1 *instanceFieldSize;
  u1 *directMethodSize;
  u1 *virtualMethodSize;
  
  pDexEncodedField pStaticField;
  pDexEncodedField pInstanceField;
  pDexEncodedMethod pDirectMethod;
  pDexEncodedMethod pVirtualMethod;
}DexClassData, *pDexClassData;

//type_item
typedef struct dexTypeItem
{
  u2 typeIdx;
}DexTypeItem, *pDexTypeItem;

//type_list
typedef struct dexTypeList
{
  u4 size;
  DexTypeItem list[1];
}DexTypeList, *pDexTypeList;

//code_item
typedef struct dexCode
{
  u2 resgisterSize;
  u2 insSize;
  u2 outsSize;
  u2 triesSize;
  u4 debugInfoOff;
  u4 insnsSize;//size of array that pInsns point to 
  u2 Insns[1];
}DexCode, *pDexCode;

//try_item
typedef struct dexTry
{
  u4 startAddr;
  u2 insnCount;
  u2 handlerOff;
}DexTry, *pDexTry;

//Link Table, Currently undefined......
typedef struct dexLink
{
  u1 bleargh;
}DexLink, *pDexLink;

//annotations_directory_item
typedef struct dexAnnotationsDirectoryItem
{
  u4 classAnnotationsOff;
  u4 fieldsSize;
  u4 methodsSize;
  u4 parametersSize;
}DexAnnotationsDirectoryItem, *pDexAnnotationsDirectoryItem;

//field_annotations_item
typedef struct dexFieldAnnotationsItem
{
  u4 fieldIdx;
  u4 annotationsOff;
}DexFieldAnnotationsItem, *pDexFieldAnnotationsItem;

//method_annotations_item
typedef struct dexMethodAnnotationsItem
{
  u4 methodIdx;
  u4 annotationsOff;
}DexMethodAnnotationsItem, *pDexMethodAnnotationsItem;

//parameter_annotations_item
typedef struct dexParameterAnnotationsItem
{
  u4  methodIdx;
  u4  annotationsOff; 
}DexParameterAnnotationsItem, *pDexParameterAnnotationsItem;

//annotation_set_ref_item
typedef struct dexAnnotationSetRefItem
{
  u4 annotationsOff;
}DexAnnotationSetRefItem, *pDexAnnotationSetRefItem;

//annotation_set_ref_list
typedef struct dexAnnotationSetRefList
{
  u4 size;
  DexAnnotationSetRefItem list[1];
}DexAnnotationSetRefList, *pDexAnnotationSetRefList;

//annotation_set_item
typedef struct dexAnnotationSetItem
{
  u4 size;
  u4 entries[1];
}DexAnnotationSetItem, *pDexAnnotationSetItem;

//annotation_item
//CAUTION:byte-aligned
typedef struct dexAnnotationItem
{
  u1 visibility;
  u1 annotation[1];
}DexAnnotationItem, *pDexAnnotationItem;

//encoded_array
typedef struct dexEncodedArray
{
  u1 array[1];
}DexEncodedArray, *pDexEncodedArray;

//lookup table for class
typedef struct dexClassLookup
{
  int size;
  int numEntries;
  struct {
	u4 classDescriptorHash;
	int classDescriptorOffset;
	int classDefOffset;
  }table[1];
}DexClassLookup, *pDexClassLookup;

//Optional header, added by DEX optimization pass
typedef struct dexOptHeader
{
  u1 magic[8];
  u4 dexOffset;
  u4 dexLength;
  u4 depsOffset;
  u4 depsLength;
  u4 optOffset;
  u4 optLength;
  u4 flags;
  u4 checksum;
}DexOptHeader, *pDexOptHeader;

//DEX FILE
typedef struct dexFile
{
  pDexOptHeader pOptHeader;//may not in a actiual DEX FILE

  pDexHeader pHeader;
  pDexStringId pStringIds;
  pDexTypeId pTypeIds;
  pDexProtoId pProtoIds;
  pDexFileId pFieldIds;
  pDexMethodId pMethodIds;
  pDexClassDef pClassDefs;
  u1 *data;
  pDexLink pLinkData;

  //below may not in a actiual DEX FILE
  pDexClassLookup pClassLookup;
  void *pRegisterMapPool;
  u1 *bassAddr;
  int overhead;
  
}DexFile, *pDexFile;

typedef struct infoUleb128
{
  u4 size;
  u4 value;
}InfoUleb128, *pInfoUleb128;

//CAUTION of leb128 data type
extern u4 AlignDex(u4 value, u4 uAlign);
extern s4 decodeUleb128(u1 *pLeb128, pInfoUleb128 pInfoleb);
extern u4 getFileSize(FILE *pDexFile);
extern s4 readDexFile(char *pFileName, u1 **ppFile);
extern s4 readDexHeader(pDexHeader pHeader);

extern void displayString(u1 *bFile, pDexStringId pStrIdItem);
extern s4 readStringTable(s4 num, u1 *fileHeader, u4 strIdOff);

extern void displayType(u1 *bFile, pDexTypeId pTypeIdItem, pDexStringId pStrIdItem);
extern s4 readTypeTable(s4 num, u1 *bFile, u4 typeIdOff, u4 strIdOff);

extern void disProtoShortDesc(u1 *bFile, u4 shortyDescriptor, pDexStringId pStrIdItem);
extern void disProtoReturnTy(u1 *bFile, u4 returnType);
extern void disProtoParams(u1 *bFile, u4 parameterOff);
  
extern void displayProto(u1 *bFile, pDexProtoId pProtoIdItem, pDexStringId pStrIdItem);
extern s4 readProtoTable(s4 num, u1 *bFile, u4 protoIdOff, u4 strIdOff);

extern void disFieldClass(u1 *bFile, u2 classId, pDexStringId pStrIdItem, pDexTypeId pTypeIdItem);
extern void disFieldType(u1 *bFile, u2 typeId, pDexStringId pStrIdItem, pDexTypeId pTypeIdItem);
extern void disFieldName(u1 *bFile, u4 nameid, pDexStringId pStrIdItem);
extern void displayField(u1 *bFile, pDexFileId pFieldIdItem);
extern s4 readFieldTable(s4 num, u1 *bFile, u4 fieldOff);

extern void disMetProtoParams(u1 *bFile, u4 parameterOff);
extern void disMethodClass(u1 *bFile, u2 classId, pDexStringId pStrIdItem, pDexTypeId pTypeIdItem);
extern void disMethodProto(u1 *bFile, u2 protoId, pDexStringId pStrIdItem, pDexTypeId pTypeIdItem, pDexProtoId pProtoIdItem);
extern void disMethodName(u1 *bFile, u4 nameId, pDexStringId pStrIdItem);
extern void displayMethod(u1 *bFile, pDexMethodId pMethodIdItem);
extern s4 readMethodTable(s4 num, u1 *bFile, u4 methodOff);

extern void displayClassDef(u1 *bFile, pDexClassDef pClassDefItem);
extern void disClsDefClass(u1 *bFile, pDexTypeId pTypeIdItem, pDexStringId pStrIdItem, u4 classOff);
extern void disClsDefSupCls(u1 *bFile, pDexTypeId pTypeIdItem, pDexStringId pStrIdItem, u4 superClsOff);
extern void disClsDefIntfce(u1 *bFile, pDexTypeId pTypeIdItem, pDexStringId pStrIdItem, u4 interfceOff);
extern void disClsDefSrc(u1 *bFile, pDexStringId pStrIdItem, u4 sourceFileId);
extern void disClsDefClsData(u1 *bFile, u4 classDataOff);
extern void disClsDataCode(u1 *bFile, u4 codeOff);
extern s4 readClassDefTable(s4 num, u1 *bFile, u4 ClassDefOff);

#endif
