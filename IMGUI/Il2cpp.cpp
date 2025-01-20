#include "Il2cpp.h"
#include "dlfcn.h"
#include <string.h>
#include <stdio.h>

/* made by feendly for ios */

namespace IL2Cpp 
{
    char* (*il2cpp_thread_get_name)(void* thread, uint32_t* len);
    void* (*il2cpp_thread_current)();
    void* (*il2cpp_thread_attach)(void* domain);
    void (*il2cpp_thread_detach)(void* thread);
    void* (*il2cpp_runtime_invoke)(const void* method, void* obj, void** params, void** exc);
    void* (*il2cpp_class_get_field_from_name)(void* klass, const char* name);
    void* (*il2cpp_class_get_method_from_name)(void* klass, const char* name, int argsCount);
    size_t (*il2cpp_field_get_offset)(void* field);
    void* (*il2cpp_domain_get)();
    void** (*il2cpp_domain_get_assemblies)(const void* domain, size_t* size);
    const void* (*il2cpp_assembly_get_image)(const void* assembly);
    const char* (*il2cpp_image_get_name)(void* image);
    void* (*il2cpp_class_from_name)(const void* image, const char* namespaze, const char* name);
    void* (*il2cpp_object_unbox)(void* obj);
    void* (*il2cpp_object_new)(const void* klass);
    void (*il2cpp_field_static_get_value)(void* field, void* value);
    void (*il2cpp_field_static_set_value)(void* field, void* value);
    uint32_t (*il2cpp_gchandle_new)(void* obj, bool pinned);
    void (*il2cpp_gchandle_free)(uint32_t gchandle);
    
    void Attach()
    {
        if (!il2cpp_thread_get_name) 
        *(void**)&il2cpp_thread_get_name = IL2Cpp::Resolve("il2cpp_thread_get_name");
        if (!il2cpp_thread_current) 
        *(void**)&il2cpp_thread_current = IL2Cpp::Resolve("il2cpp_thread_current");
        if (!il2cpp_thread_attach) 
        *(void**)&il2cpp_thread_attach = IL2Cpp::Resolve("il2cpp_thread_attach");
        if (!il2cpp_thread_detach) 
        *(void**)&il2cpp_thread_detach = IL2Cpp::Resolve("il2cpp_thread_detach");
        if (!il2cpp_runtime_invoke) 
        *(void**)&il2cpp_runtime_invoke = IL2Cpp::Resolve("il2cpp_runtime_invoke");
        if (!il2cpp_class_get_field_from_name) 
        *(void**)&il2cpp_class_get_field_from_name = IL2Cpp::Resolve("il2cpp_class_get_field_from_name");
        if (!il2cpp_class_get_method_from_name) 
        *(void**)&il2cpp_class_get_method_from_name = IL2Cpp::Resolve("il2cpp_class_get_method_from_name");
        if (!il2cpp_field_get_offset) 
        *(void**)&il2cpp_field_get_offset = IL2Cpp::Resolve("il2cpp_field_get_offset");
        if (!il2cpp_domain_get) 
        *(void**)&il2cpp_domain_get = IL2Cpp::Resolve("il2cpp_domain_get");
        if (!il2cpp_domain_get_assemblies) 
        *(void**)&il2cpp_domain_get_assemblies = IL2Cpp::Resolve("il2cpp_domain_get_assemblies");
        if (!il2cpp_assembly_get_image) 
        *(void**)&il2cpp_assembly_get_image = IL2Cpp::Resolve("il2cpp_assembly_get_image");
        if (!il2cpp_image_get_name) 
        *(void**)&il2cpp_image_get_name = IL2Cpp::Resolve("il2cpp_image_get_name");
        if (!il2cpp_class_from_name) 
        *(void**)&il2cpp_class_from_name = IL2Cpp::Resolve("il2cpp_class_from_name");
        if (!il2cpp_object_unbox) 
        *(void**)&il2cpp_object_unbox = IL2Cpp::Resolve("il2cpp_object_unbox");
        if (!il2cpp_object_new) 
        *(void**)&il2cpp_object_new = IL2Cpp::Resolve("il2cpp_object_new");
        if (!il2cpp_field_static_get_value) 
        *(void**)&il2cpp_field_static_get_value = IL2Cpp::Resolve("il2cpp_field_static_get_value");
        if (!il2cpp_field_static_set_value) 
        *(void**)&il2cpp_field_static_set_value = IL2Cpp::Resolve("il2cpp_field_static_set_value");
        if (!il2cpp_gchandle_new) 
        *(void**)&il2cpp_gchandle_new = IL2Cpp::Resolve("il2cpp_gchandle_new");
        if (!il2cpp_gchandle_free) 
        *(void**)&il2cpp_gchandle_free = IL2Cpp::Resolve("il2cpp_gchandle_free");
    }

    void* Resolve(const char* symbol)
    {   
        void* mode = RTLD_DEFAULT;
        void* fptr = dlsym(mode, symbol);

        if (!fptr)
        {
            printf("Il2cpp: couldn't find %s", symbol);
            return nullptr;
        }

        return fptr;
    }

    void* GetImage(const char* img_name)
    {
        void* domain = il2cpp_domain_get();

        if (!domain) 
        {
            return nullptr;
        }

        size_t size;
        void** assemblies = il2cpp_domain_get_assemblies(domain, &size);

        for (int i = 0; i < size; i++) {
            void *cur = (void*)il2cpp_assembly_get_image(assemblies[i]); 

            if(strcmp(img_name, il2cpp_image_get_name(cur)) == 0) {
                return cur;
            }
        
        }
        return nullptr;
    }

    void* GetClass(const char* image, const char* namespaze, const char* clazz)
    {
        void* img = GetImage(image);

        if (!img)
        {
            return nullptr;
        }
            
        void* klass = il2cpp_class_from_name(img, namespaze, clazz);

        if (!klass) 
        {
            return nullptr;
        }

        return klass;
    }

    const void* GetMethodOffset(const char* image, const char* namespaze, const char* klass_name, const char* name, int argsCount)
    {   
        void* img = GetImage(image);

        if(!img) 
        {
            return nullptr;
        }

        void* klass = il2cpp_class_from_name(img, namespaze, klass_name);

        if(!klass) 
        {
            return nullptr;
        }

        void** method = (void **)il2cpp_class_get_method_from_name(klass, name, argsCount);

        if (!method) 
        {
            return nullptr;
        }

        return *method;
    }

    void GetStaticFieldValue(const char* image, const char* namespaze, const char* clazz, const char* name, void* output)
    {
        void* img = GetImage(image);

        if (!img) 
        {
            return;
        }

        void* klass = il2cpp_class_from_name(img, namespaze, clazz);

        if (!klass) 
        {
            return;
        }

        void* field = il2cpp_class_get_field_from_name(klass, name);

        if (!field)
        {
            return;
        }

        il2cpp_field_static_get_value(field, output);
    }

    void SetStaticFieldValue(const char* image, const char* namespaze, const char* clazz, const char* name, void* value) 
    {
        void* img = GetImage(image);

        if (!img) 
        {
            return;
        }

        void* klass = il2cpp_class_from_name(img, namespaze, clazz);

        if (!klass) 
        {
            return;
        }

        void* field = il2cpp_class_get_field_from_name(klass, name);

        if(!field) 
        {
            return;
        }

        il2cpp_field_static_set_value(field, value);
    }

}
