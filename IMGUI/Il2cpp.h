#pragma once

#include <stdio.h>
#include <string>
#include <inttypes.h>
#include <codecvt>
#include <locale>
#include <dlfcn.h>

using namespace std;

typedef void(*Il2CppMethodPointer)();

struct MethodInfo;

struct VirtualInvokeData
{
    Il2CppMethodPointer methodPtr;
    const MethodInfo* method;
};

struct Il2CppType
{
    void* data;
    unsigned int bits;
};

struct Il2CppClass;

struct Il2CppObject
{
    Il2CppClass *klass;
    void *monitor;
};

union Il2CppRGCTXData
{
    void* rgctxDataDummy;
    const MethodInfo* method;
    const Il2CppType* type;
    Il2CppClass* klass;
};

struct Il2CppClass_1
{
    void* image;
    void* gc_desc;
    const char* name;
    const char* namespaze;
    Il2CppType* byval_arg;
    Il2CppType* this_arg;
    Il2CppClass* element_class;
    Il2CppClass* castClass;
    Il2CppClass* declaringType;
    Il2CppClass* parent;
    void *generic_class;
    void* typeDefinition;
    void* interopData;
    void* fields;
    void* events;
    void* properties;
    void* methods;
    Il2CppClass** nestedTypes;
    Il2CppClass** implementedInterfaces;
    void* interfaceOffsets;
};

struct Il2CppClass_2
{
    Il2CppClass** typeHierarchy;
    uint32_t cctor_started;
    uint32_t cctor_finished;
    uint64_t cctor_thread;
    int32_t genericContainerIndex;
    int32_t customAttributeIndex;
    uint32_t instance_size;
    uint32_t actualSize;
    uint32_t element_size;
    int32_t native_size;
    uint32_t static_fields_size;
    uint32_t thread_static_fields_size;
    int32_t thread_static_fields_offset;
    uint32_t flags;
    uint32_t token;
    uint16_t method_count;
    uint16_t property_count;
    uint16_t field_count;
    uint16_t event_count;
    uint16_t nested_type_count;
    uint16_t vtable_count;
    uint16_t interfaces_count;
    uint16_t interface_offsets_count;
    uint8_t typeHierarchyDepth;
    uint8_t genericRecursionDepth;
    uint8_t rank;
    uint8_t minimumAlignment;
    uint8_t packingSize;
    uint8_t bitflags1;
    uint8_t bitflags2;
};

struct Il2CppClass
{
    Il2CppClass_1 _1;
    void* static_fields;
    Il2CppRGCTXData* rgctx_data;
    Il2CppClass_2 _2;
    VirtualInvokeData vtable[255];
};

typedef int32_t il2cpp_array_size_t;
typedef int32_t il2cpp_array_lower_bound_t;
struct Il2CppArrayBounds
{
    il2cpp_array_size_t length;
    il2cpp_array_lower_bound_t lower_bound;
};

struct MethodInfo
{
    Il2CppMethodPointer methodPointer;
    void* invoker_method;
    const char* name;
    Il2CppClass *declaring_type;
    const Il2CppType *return_type;
    const void* parameters;
    union
    {
        const Il2CppRGCTXData* rgctx_data;
        const void* methodDefinition;
    };
    union
    {
        const void* genericMethod;
        const void* genericContainer;
    };
    int32_t customAttributeIndex;
    uint32_t token;
    uint16_t flags;
    uint16_t iflags;
    uint16_t slot;
    uint8_t parameters_count;
    uint8_t bitflags;
};

template<typename T> struct Il2CppArray {
    Il2CppClass *klass;
    void *monitor;
    void *bounds;
    int max_length;
    T m_Items[65535];

    int getLength() {
        return max_length;
    }

    T *getPointer() {
        return (T *)m_Items;
    }

    T &operator[](int i) {
        return m_Items[i];
    }

    T &operator[](int i) const {
        return m_Items[i];
    }

    std::vector<T> toCPPlist() {
        std::vector<T> ret;
        ret.reserve(max_length);

        for (int i = 0; i < max_length; i++) {
            ret.push_back(m_Items[i]);
        }

        return ret;
    }
};

template<typename T>
using Array = Il2CppArray<T>;

template<typename T> struct Il2CppList {
    Il2CppClass *klass;
    void *unk1;
    Il2CppArray<T> *items;
    int size;
    int version;

    T *getItems() {
        return items->getPointer();
    }

    int getSize() {
        return size;
    }

    int getVersion() {
        return version;
    }

    T &operator[](int i) {
        return items->m_Items[i];
    }

    T &operator[](int i) const {
        return items->m_Items[i];
    }

      std::vector<T> toCPPlist() {
        std::vector<T> ret;
        ret.reserve(size); // Reserve space in the vector for the items.

        for (int i = 0; i < size; i++) {
            ret.push_back(items->m_Items[i]);
        }

        return ret;
    }
};

template<typename T>
using List = Il2CppList<T>;

template<typename K, typename V> struct Il2CppDictionary {
    Il2CppClass *klass;
    void *unk1;
    Il2CppArray<int **> *table;
    Il2CppArray<void **> *linkSlots;
    Il2CppArray<K> *keys;
    Il2CppArray<V> *values;
    int touchedSlots;
    int emptySlot;
    int size;

    K *getKeys() {
        return keys->getPointer();
    }

    V *getValues() {
        return values->getPointer();
    }

    int getNumKeys() {
        return keys->getLength();
    }

    int getNumValues() {
        return values->getLength();
    }

    int getSize() {
        return size;
    }
};

template<typename K, typename V>
using Dictionary = Il2CppDictionary<K, V>;

namespace IL2Cpp 
{
    extern char* (*il2cpp_thread_get_name)(void* thread, uint32_t* len);
    extern void* (*il2cpp_thread_current)();
    extern void* (*il2cpp_thread_attach)(void* domain);
    extern void (*il2cpp_thread_detach)(void* thread);
    extern void* (*il2cpp_runtime_invoke)(const void* method, void* obj, void** params, void** exc);
    extern void* (*il2cpp_class_get_field_from_name)(void* klass, const char* name);
    extern void* (*il2cpp_class_get_method_from_name)(void* klass, const char* name, int argsCount);
    extern size_t (*il2cpp_field_get_offset)(void* field);
    extern void* (*il2cpp_domain_get)();
    extern void** (*il2cpp_domain_get_assemblies)(const void* domain, size_t* size);
    extern const void* (*il2cpp_assembly_get_image)(const void* assembly);
    extern const char* (*il2cpp_image_get_name)(void* image);
    extern void* (*il2cpp_class_from_name)(const void* image, const char* namespaze, const char* name);
    extern void* (*il2cpp_object_unbox)(void* obj);
    extern void* (*il2cpp_object_new)(const void* klass);
    extern void (*il2cpp_field_static_get_value)(void* field, void* value);
    extern void (*il2cpp_field_static_set_value)(void* field, void* value);
    extern uint32_t (*il2cpp_gchandle_new)(void* obj, bool pinned);
    extern void (*il2cpp_gchandle_free)(uint32_t gchandle);

    void Attach();
    void *Resolve(const char *);
    void *GetImage(const char* image);
    void *GetClass(const char *image, const char *namespaze, const char *clazz);
    const void *GetMethodOffset(const char* image, const char* namespaze, const char* klass, const char* name, int argsCount = 0);
    void GetStaticFieldValue(const char *image, const char *namespaze, const char *clazz, const char *name, void *output);
    void SetStaticFieldValue(const char *image, const char *namespaze, const char *clazz, const char *name, void *value);
}

