// Theme by: Thiện 131 
// Share by: @dothanh1110 (đc cấp phép)
// mấy con chó share ko gắn nguồn chết đi || và mấy con chó leak trc đó cx thế nhé
// Zalo: https://zalo.me/g/pmselp698
#import "FileKoRac/ImGuiDrawView.h"
#include <mach/mach.h>
#include <mach/mach_init.h>
#import <Metal/Metal.h>
#import "FileKoRac/ImGuiLoad.h"
#import "FileKoRac/PubgLoad.h"
#import <MetalKit/MetalKit.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#include <unistd.h>
#import <dlfcn.h>
#include <libgen.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include <mach/vm_page_size.h>
#include <Foundation/Foundation.h>
#include <map>
#include <deque>
#include <vector>
#include <array>
// #import "FileKoRac/beaus.h"
#import "FileKoRac/hoves.h"
#include <chrono>
#include <iomanip>
#include <sstream>
#include <ctime>
//#include <iostream>
//#include <cstring>
//#include <thread>
//#include <chrono>
//ETC//
#include "IMGUI/imgui.h"
#include "IMGUI/imgui_impl_metal.h"
#import "FileKoRac/RKDropdownAlert.h"
#import "FileKoRac/mahoa.h"
#import "FileKoRac/MonoString.h"

#import "FileKoRac/lib.h"


//Patch H5GG HOOK//
#include "FileKoRac/dbdef.h"
#include "Settings.h"
#include <sys/sysctl.h>
#import <mach/task_info.h>
#import <mach/task.h>
#include <sys/stat.h>
#include <unistd.h>
#import <Foundation/Foundation.h>
#include <unordered_map>


#define DEBUG

#ifdef DEBUG
#define log(...) NSLog(__VA_ARGS__)
#else
#define log(...)
#endif

//HOOK BEGIN
#pragma GCC diagnostic ignored "-Warc-performSelector-leaks"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wincomplete-implementation"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic ignored "-W#warnings"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wreorder"
#pragma GCC diagnostic ignored "-Wwritable-strings"
#pragma GCC diagnostic ignored "-Wtrigraphs"

#define STATIC_HOOK_CODEPAGE_SIZE PAGE_SIZE
#define STATIC_HOOK_DATAPAGE_SIZE PAGE_SIZE

// ImFont* ico = nullptr;
// ImFont* ico_combo = nullptr;
// ImFont* ico_button = nullptr;
// ImFont* ico_grande = nullptr;
// ImFont* segu = nullptr;
// ImFont* default_segu = nullptr;
// ImFont* bold_segu = nullptr;


// C++ version made by Lavochka

uint64_t va2rva(struct mach_header_64* header, uint64_t va)
{
    uint64_t rva = va;
    
    uint64_t header_vaddr = -1;
    struct load_command* lc = (struct load_command*)((UInt64)header + sizeof(*header));
    for (int i = 0; i < header->ncmds; i++) {
        
        if (lc->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 * seg = (struct segment_command_64 *)lc;
            
            if(seg->fileoff==0 && seg->filesize>0)
            {
                if(header_vaddr != -1) {
                    log(@"multi header mapping! %s", seg->segname);
                    return 0;
                }
                header_vaddr = seg->vmaddr;
            }
        }
        
        lc = (struct load_command *) ((char *)lc + lc->cmdsize);
    }
    
    if(header_vaddr != -1) {
        //log(@"header_vaddr=%p", header_vaddr);
        rva -= header_vaddr;
    }
    
    //log(@"va2rva %p=>%p", va, rva);
    
    return rva;
}
// C++ version made by Lavochka
void* rva2data(struct mach_header_64* header, uint64_t rva)
{
    uint64_t header_vaddr = -1;
    struct load_command* lc = (struct load_command*)((UInt64)header + sizeof(*header));
    for (int i = 0; i < header->ncmds; i++) {
        
        if (lc->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 * seg = (struct segment_command_64 *)lc;
            
            if(seg->fileoff==0 && seg->filesize>0)
            {
                if(header_vaddr != -1) {
                    log(@"multi header mapping! %s", seg->segname);
                    return NULL;
                }
                header_vaddr = seg->vmaddr;
            }
        }
        
        lc = (struct load_command *) ((char *)lc + lc->cmdsize);
    }
    
    if(header_vaddr != -1) {
        log(@"header_vaddr=%p", header_vaddr);
        rva += header_vaddr;
    }
    
    //struct load_command*
    lc = (struct load_command*)((UInt64)header + sizeof(*header));
    for (int i = 0; i < header->ncmds; i++) {

        if (lc->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 * seg = (struct segment_command_64 *) lc;
            
            uint64_t seg_vmaddr_start = seg->vmaddr;
            uint64_t seg_vmaddr_end   = seg_vmaddr_start + seg->vmsize;
            if ((uint64_t)rva >= seg_vmaddr_start && (uint64_t)rva < seg_vmaddr_end)
            {
              // some section like '__bss', '__common'
              uint64_t offset = (uint64_t)rva - seg_vmaddr_start;
              if (offset > seg->filesize) {
                return NULL;
              }
                
              log(@"vaddr=%p offset=%p\n", rva, seg->fileoff + offset);
              return (void*)((uint64_t)header + seg->fileoff + offset);
            }
        }

        lc = (struct load_command *) ((char *)lc + lc->cmdsize);
    }
    
    return NULL;
}

// C++ version made by Lavochka
NSMutableData* load_macho_data(NSString* path)
{
    NSMutableData* macho = [NSMutableData dataWithContentsOfFile:path];
    if(!macho) return nil;
    
    UInt32 magic = *(uint32_t*)macho.mutableBytes;
    if(magic==FAT_CIGAM)
    {
        struct fat_header* fathdr = (struct fat_header*)macho.mutableBytes;
        struct fat_arch* archdr = (struct fat_arch*)((UInt64)fathdr + sizeof(*fathdr));
        log(@"add_hook_section nfat_arch=%d", NXSwapLong(fathdr->nfat_arch));
        if(NXSwapLong(fathdr->nfat_arch) != 1) {
            log(@"macho has too many arch!");
            return nil;
        }
        
        if(NXSwapLong(archdr->cputype) != CPU_TYPE_ARM64 || archdr->cpusubtype!=0) {
            log(@"macho arch not support!");
            return nil;
        }
        log(@"subarch=%x %x", NXSwapLong(archdr->offset), NXSwapLong(archdr->size));
        macho = [NSMutableData dataWithData:
                 [macho subdataWithRange:NSMakeRange(NXSwapLong(archdr->offset), NXSwapLong(archdr->size))]];
        
    } else if(magic==FAT_CIGAM_64)
    {
        struct fat_header* fathdr = (struct fat_header*)macho.mutableBytes;
        struct fat_arch_64* archdr = (struct fat_arch_64*)((UInt64)fathdr + sizeof(*fathdr));
        log(@"macho nfat_arch=%d", NXSwapLong(fathdr->nfat_arch));
        if(NXSwapLong(fathdr->nfat_arch) != 1) {
            log(@"macho has too many arch!");
            return nil;
        }
        
        if(NXSwapLong(archdr->cputype) != CPU_TYPE_ARM64 || archdr->cpusubtype!=0) {
            log(@"macho arch not support!");
            return nil;
        }
        log(@"subarch=%x %x", NXSwapLong(archdr->offset), NXSwapLong(archdr->size));
        macho = [NSMutableData dataWithData:
                 [macho subdataWithRange:NSMakeRange(NXSwapLong(archdr->offset), NXSwapLong(archdr->size))]];
        
    } else if(magic != MH_MAGIC_64) {
        log(@"macho arch not support!");
        return nil;
    }
    
    return macho;
}

NSMutableData* add_hook_section(NSMutableData* macho)
{
    struct mach_header_64* header = (struct mach_header_64*)macho.mutableBytes;
    log(@"macho %x %x", header->magic, macho.length);
    
    uint64_t vm_end = 0;
    uint64_t min_section_offset = 0;
    struct segment_command_64* linkedit_seg = NULL;
    
    struct load_command* lc = (struct load_command*)((UInt64)header + sizeof(*header));
    for (int i = 0; i < header->ncmds; i++) {
        log(@"macho load cmd=%d", lc->cmd);
        
        if (lc->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 * seg = (struct segment_command_64 *) lc;
            
            log(@"segment: %s file=%x:%x vm=%p:%p\n", seg->segname, seg->fileoff, seg->filesize, seg->vmaddr, seg->vmsize);
            
            if(strcmp(seg->segname,SEG_LINKEDIT)==0)
                linkedit_seg = seg;
            else
            if(seg->vmsize && vm_end<(seg->vmaddr+seg->vmsize))
                vm_end = seg->vmaddr+seg->vmsize;
            
            struct section_64* sec = (struct section_64*)((uint64_t)seg+sizeof(*seg));
            for(int j=0; j<seg->nsects; j++)
            {
                log(@"section[%d] = %s/%s offset=%x vm=%p:%p", j, sec[j].segname, sec[j].sectname,
                      sec[j].offset, sec[j].addr, sec[j].size);
                
                if(min_section_offset < sec[j].offset)
                    min_section_offset = sec[j].offset;
            }
        }
        
        lc = (struct load_command *) ((char *)lc + lc->cmdsize);
    }
    
    if(!min_section_offset || !vm_end || !linkedit_seg) {
        log(@"cannot parse macho file!");
        return nil;
    }
    
    log(@"min_section_offset=%x vm_end=%p", min_section_offset, vm_end);
    
    NSRange linkedit_range = NSMakeRange(linkedit_seg->fileoff, linkedit_seg->filesize);
    NSData* linkedit_data = [macho subdataWithRange:linkedit_range];
    [macho replaceBytesInRange:linkedit_range withBytes:nil length:0];
    
    
    struct segment_command_64 text_seg = {
        .cmd = LC_SEGMENT_64,
        .cmdsize=sizeof(struct segment_command_64)+sizeof(struct section_64),
        .segname = {"_PP_OFFSETS"},
        .vmaddr = vm_end,
        .vmsize = STATIC_HOOK_CODEPAGE_SIZE,
        .fileoff = macho.length,
        .filesize = STATIC_HOOK_CODEPAGE_SIZE,
        .maxprot = VM_PROT_READ|VM_PROT_EXECUTE,
        .initprot = VM_PROT_READ|VM_PROT_EXECUTE,
        .nsects = 1,
        .flags = 0
    };
    struct section_64 text_sec = {
        .segname = {"_PP_OFFSETS"},
        .sectname = {"_pp_offsets"},
        .addr = text_seg.vmaddr,
        .size = text_seg.vmsize,
        .offset = (uint32_t)text_seg.fileoff,
        .align = 0,
        .reloff = 0,
        .nreloc = 0,
        .flags = S_ATTR_PURE_INSTRUCTIONS|S_ATTR_SOME_INSTRUCTIONS,
        .reserved1 = 0, .reserved2 = 0, .reserved3 = 0
    };
    
    struct segment_command_64 data_seg = {
        .cmd = LC_SEGMENT_64,
        .cmdsize=sizeof(struct segment_command_64)+sizeof(struct section_64),
        .segname = {"_PP_BYTESVA"},
        .vmaddr = text_seg.vmaddr+text_seg.vmsize,
        .vmsize = STATIC_HOOK_CODEPAGE_SIZE,
        .fileoff = text_seg.fileoff+text_seg.filesize,
        .filesize = STATIC_HOOK_CODEPAGE_SIZE,
        .maxprot = VM_PROT_READ|VM_PROT_WRITE,
        .initprot = VM_PROT_READ|VM_PROT_WRITE,
        .nsects = 1,
        .flags = 0
    };
    struct section_64 data_sec = {
        .segname = {"_PP_BYTESVA"},
        .sectname = {"_pp_bytesva"},
        .addr = data_seg.vmaddr,
        .size = data_seg.vmsize,
        .offset = (uint32_t)data_seg.fileoff,
        .align = 0,
        .reloff = 0,
        .nreloc = 0,
        .flags = 0, //S_ZEROFILL,
        .reserved1 = 0, .reserved2 = 0, .reserved3 = 0
    };
    
    uint64_t linkedit_cmd_offset = (uint64_t)linkedit_seg - ((uint64_t)header+sizeof(*header));
    unsigned char* cmds = (unsigned char*)malloc(header->sizeofcmds);
    memcpy(cmds, (unsigned char*)header+sizeof(*header), header->sizeofcmds);
    unsigned char* patch = (unsigned char*)header +sizeof(*header) + linkedit_cmd_offset;
    
    memcpy(patch, &text_seg, sizeof(text_seg));
    patch += sizeof(text_seg);
    memcpy(patch, &text_sec, sizeof(text_sec));
    patch += sizeof(text_sec);

    memcpy(patch, &data_seg, sizeof(data_seg));
    patch += sizeof(data_seg);
    memcpy(patch, &data_sec, sizeof(data_sec));
    patch += sizeof(data_sec);
    
    memcpy(patch, cmds+linkedit_cmd_offset, header->sizeofcmds-linkedit_cmd_offset);
    
    linkedit_seg = (struct segment_command_64*)patch;
    
    header->ncmds += 2;
    header->sizeofcmds += text_seg.cmdsize + data_seg.cmdsize;
    
    linkedit_seg->fileoff = macho.length+text_seg.filesize+data_seg.filesize;
    linkedit_seg->vmaddr = vm_end+text_seg.vmsize+data_seg.vmsize;
    // C++ version made by Lavochka
    // fix load_command
    struct load_command *load_cmd = (struct load_command *)((uint64_t)header + sizeof(*header));
    for (int i = 0; i < header->ncmds;
         i++, load_cmd = (struct load_command *)((uint64_t)load_cmd + load_cmd->cmdsize))
    {
        uint64_t fixoffset = text_seg.filesize+data_seg.filesize;// + linkedit_seg->filesize;
        
      switch (load_cmd->cmd)
      {
          case LC_DYLD_INFO:
          case LC_DYLD_INFO_ONLY:
          {
            struct dyld_info_command *tmp = (struct dyld_info_command *)load_cmd;
            tmp->rebase_off += fixoffset;
            tmp->bind_off += fixoffset;
            if (tmp->weak_bind_off)
              tmp->weak_bind_off += fixoffset;
            if (tmp->lazy_bind_off)
              tmp->lazy_bind_off += fixoffset;
            if (tmp->export_off)
              tmp->export_off += fixoffset;
            log(@"[-] fix LC_DYLD_INFO_ done\n");
          } break;
              
          case LC_SYMTAB:
          {
            struct symtab_command *tmp = (struct symtab_command *)load_cmd;
            if (tmp->symoff)
              tmp->symoff += fixoffset;
            if (tmp->stroff)
              tmp->stroff += fixoffset;
            log(@"[-] fix LC_SYMTAB done\n");
          } break;
              
          case LC_DYSYMTAB:
          {
            struct dysymtab_command *tmp = (struct dysymtab_command *)load_cmd;
            if (tmp->tocoff)
              tmp->tocoff += fixoffset;
            if (tmp->modtaboff)
              tmp->modtaboff += fixoffset;
            if (tmp->extrefsymoff)
              tmp->extrefsymoff += fixoffset;
            if (tmp->indirectsymoff)
              tmp->indirectsymoff += fixoffset;
            if (tmp->extreloff)
              tmp->extreloff += fixoffset;
            if (tmp->locreloff)
              tmp->locreloff += fixoffset;
            log(@"[-] fix LC_DYSYMTAB done\n");
          } break;
              
          case LC_FUNCTION_STARTS:
          case LC_DATA_IN_CODE:
          case LC_CODE_SIGNATURE:
          case LC_SEGMENT_SPLIT_INFO:
          case LC_DYLIB_CODE_SIGN_DRS:
          case LC_LINKER_OPTIMIZATION_HINT:
          case LC_DYLD_EXPORTS_TRIE:
          case LC_DYLD_CHAINED_FIXUPS:
          {
            struct linkedit_data_command *tmp = (struct linkedit_data_command *)load_cmd;
            if (tmp->dataoff) tmp->dataoff += fixoffset;
            log(@"[-] fix linkedit_data_command done\n");
          } break;
      }
    }
    
    if(min_section_offset < (sizeof(struct mach_header_64)+header->sizeofcmds)) {
        log(@"macho header has no enough space!");
        return nil;
    }
    
    unsigned char* codepage = (unsigned char*)malloc(text_seg.vmsize);
    memset(codepage, 0xFF, text_seg.vmsize);
    [macho appendBytes:codepage length:text_seg.vmsize];
    free(codepage);
    
    unsigned char* datapage = (unsigned char*)malloc(data_seg.vmsize);
    memset(datapage, 0, data_seg.vmsize);
    //for(int i=0;i<data_seg.vmsize;i++) datapage[i]=i;
    [macho appendBytes:datapage length:data_seg.vmsize];
    free(datapage);
    
    [macho appendData:linkedit_data];
    
    log(@"macho file size=%x", macho.length);
    
    return macho;
}

bool hex2bytes(char* bytes, unsigned char* buffer)
{
    size_t len=strlen(bytes);
    for(int i=0; i<len; i++) {
        char _byte = bytes[i];
        if(_byte>='0' && _byte<='9')
            _byte -= '0';
        else if(_byte>='a' && _byte<='f')
            _byte -= 'a'-10;
        else if(_byte>='A' && _byte<='F')
            _byte -= 'A'-10;
        else
            return false;
        
        buffer[i/2] &= (i+1)%2 ? 0x0F : 0xF0;
        buffer[i/2] |= _byte << (((i+1)%2)*4);
        
    }
    return true;
}

uint64_t calc_patch_hash(uint64_t vaddr, char* patch)
{
    return [[[NSString stringWithUTF8String:patch] lowercaseString] hash] ^ vaddr;
}

NSString* Hello(char* machoPath, uint64_t vaddr, char* patch)
{
    static NSMutableDictionary* gStaticInlineHookMachO = [[NSMutableDictionary alloc] init];
    
    NSString* path = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:[NSString stringWithUTF8String:machoPath]];
        
    NSString* newPath = gStaticInlineHookMachO[path];
    
    NSMutableData* macho=nil;

    if(newPath) {
        macho = load_macho_data(newPath);
        if(!macho) return [NSString stringWithFormat:@"?????(can't find file):\n Documents/hackkkkne/%s", machoPath];
    } else {
        macho = load_macho_data(path);
        if(!macho) return [NSString stringWithFormat:@"??????(can't read file):\n.app/%s", machoPath];
    }
    
    uint32_t cryptid = 0;
    struct mach_header_64* header = NULL;
    struct segment_command_64* text_seg = NULL;
    struct segment_command_64* data_seg = NULL;
    
    while(true) {
        
        header = (struct mach_header_64*)macho.mutableBytes;
        log(@"macho %x %x", header->magic, macho.length);
        
        struct load_command* lc = (struct load_command*)((UInt64)header + sizeof(*header));
        for (int i = 0; i < header->ncmds; i++) {
            if (lc->cmd == LC_SEGMENT_64) {
                struct segment_command_64 * seg = (struct segment_command_64 *) lc;
                if(strcmp(seg->segname,"_PP_OFFSETS")==0)
                    text_seg = seg;
                if(strcmp(seg->segname,"_PP_BYTESVA")==0)
                    data_seg = seg;
            }
            if(lc->cmd == LC_ENCRYPTION_INFO_64) {
                struct encryption_info_command_64* info = (struct encryption_info_command_64*)lc;
                if(cryptid==0) cryptid = info->cryptid;
            }
            lc = (struct load_command *) ((char *)lc + lc->cmdsize);
        }
        
        if(text_seg && data_seg) {
            log(@"hook section found!");
            break;
        }
        
        macho = add_hook_section(macho);
        if(!macho) {
            return @"add_hook_section error!";
        }
    }
    
    if(cryptid != 0) {
        return @"?app?????!\nthis app is not decrypted!";
    }
    
    if(!text_seg || !data_seg) {
        return @"????machO??!\ncan not parse machO file!";
    }
    
    uint64_t funcRVA = vaddr & ~(4-1);
    void *funcData = rva2data(header, funcRVA);
    //*(uint32_t*)funcData = 0x58000020; //ldr x0, #4 test
    
    if(!funcData) {
        return @"?????!\nInvalid offset!";
    }
    
    // C++ version made by Lavochka
    void* patch_bytes=NULL; uint64_t patch_size=0;
    
    if(patch && patch[0]) {
        uint64_t patch_end = vaddr + (strlen(patch)+1)/2;
        uint64_t code_end = (patch_end+4-1) & ~(4-1);
        
        patch_size = code_end - funcRVA;
        
        log(@"codepath %p %s : %p~%p~%p %x", vaddr, patch, funcRVA, patch_end, code_end, patch_size);
        
        NSMutableData* patchBytes = [[NSMutableData alloc] initWithLength:patch_size];
        patch_bytes = patchBytes.mutableBytes;
        
        memcpy(patch_bytes, funcData, patch_size);
        
        if(!hex2bytes(patch, (uint8_t*)patch_bytes+vaddr%4))
            return @"?????????!\nThe bytes to patch are incorrect!";

    } else if(vaddr % 4) {
        return @"?????!\nThe offset is not aligned!";
    }
    
    
    uint64_t targetRVA = va2rva(header, text_seg->vmaddr);
    void* targetData = rva2data(header, targetRVA);
    
    
    uint64_t InstrumentBridgeRVA = targetRVA;
    
    uint64_t dataRVA = va2rva(header, data_seg->vmaddr);
    void* dataData = rva2data(header, dataRVA);
    
    StaticInlineHookBlock* hookBlock = (StaticInlineHookBlock*)dataData;
    StaticInlineHookBlock* hookBlockRVA = NULL;
    for(int i=0; i<STATIC_HOOK_CODEPAGE_SIZE/sizeof(StaticInlineHookBlock); i++)
    {
        if(hookBlock[i].hook_vaddr==funcRVA)
        {
            if(patch && patch[0] && hookBlock[i].patch_hash!=calc_patch_hash(vaddr, patch))
                return @"????????, ??????????!\nThe bytes to patch have changed, please revert to original file and try again";
            
            if(newPath)
                return @"??????, ??APP?Documents/static-inline-hook???????????ipa??.app?????????!\nThe offset is already patched! Please replace the patched file in the APP's Documents/static-inline-hook directory to the .app directory in the ipa and re-sign and reinstall!";
            
            return @"?HOOK?????!\nThe offset to hook is already patched!";
        }
        
        if( funcRVA>hookBlock[i].hook_vaddr &&
           ( funcRVA < (hookBlock[i].hook_vaddr+hookBlock[i].hook_size) || funcRVA < (hookBlock[i].hook_vaddr+hookBlock[i].patch_size) )
          ) {
            return @"???????!\nThe offset is occupied!";
        }
        
        if(hookBlock[i].hook_vaddr==0)
        {
            hookBlock = &hookBlock[i];
            hookBlockRVA = (StaticInlineHookBlock*)(dataRVA + i*sizeof(StaticInlineHookBlock));
            
            if(i == 0)
            {
                int codesize = dobby_create_instrument_bridge(targetData);
                
                targetRVA += codesize;
                *(uint64_t*)&targetData += codesize;
            }
            else
            {
                StaticInlineHookBlock* lastBlock = hookBlock - 1;
                targetRVA = lastBlock->code_vaddr + lastBlock->code_size;
                targetData = rva2data(header, targetRVA);
            }
            
            log(@"found empty StaticInlineHookBlock %d %p=>%p\n", i, targetRVA, targetData);
            
            break;
        }
    }
    if(!hookBlockRVA) {
        return @"????????!\nHOOK count full!";
    }
    
    log(@"func: %p=>%p target: %p=>%p\n", funcRVA, funcData, targetRVA, targetData);
    
    if(!dobby_static_inline_hook(hookBlock, hookBlockRVA, funcRVA, funcData, targetRVA, targetData,
                                 InstrumentBridgeRVA, patch_bytes, patch_size))
    {
        return @"???????!\ncan not patch the offset";
    }
    
    if(patch && patch[0]) {
        hookBlock->patch_size = patch_size;
        hookBlock->patch_hash = calc_patch_hash(vaddr, patch);
    }
    

    NSString* savePath = [NSString stringWithFormat:@"%@/Documents/hellohackerlo/%s", NSHomeDirectory(), machoPath];
    [NSFileManager.defaultManager createDirectoryAtPath:[NSString stringWithUTF8String:dirname((char*)savePath.UTF8String)] withIntermediateDirectories:YES attributes:nil error:nil];
    
    if(![macho writeToFile:savePath atomically:NO])
        return @"??????!\ncan not write to file!";
    
    gStaticInlineHookMachO[path] = savePath;
    return @"??????, ????????APP?Documents/static-inline-hook???, ?????????????ipa??.app?????????!\nThe offset has not been patched, the patched file will be generated in the Documents/static-inline-hook directory of the APP, please replace all the files in this directory to the .app directory in the ipa and re-sign and reinstall!";
}



// C++ version made by Lavochka
void* find_module_by_path(char* machoPath)
{
    NSString* path = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:[NSString stringWithUTF8String:machoPath]];
    
    for(int i=0; i< _dyld_image_count(); i++) {

        const char* fpath = _dyld_get_image_name(i);
        void* baseaddr = (void*)_dyld_get_image_header(i);
        void* slide = (void*)_dyld_get_image_vmaddr_slide(i); //no use
        
        if([path isEqualToString:[NSString stringWithUTF8String:fpath]])
            return baseaddr;
    }
    
    return NULL;
}

StaticInlineHookBlock* find_hook_block(void* base, uint64_t vaddr)
{
    struct segment_command_64* text_seg = NULL;
    struct segment_command_64* data_seg = NULL;
    
    struct mach_header_64* header = (struct mach_header_64*)base;
    
    struct load_command* lc = (struct load_command*)((UInt64)header + sizeof(*header));
    for (int i = 0; i < header->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 * seg = (struct segment_command_64 *) lc;
            if(strcmp(seg->segname,"_PP_OFFSETS")==0)
                text_seg = seg;
            if(strcmp(seg->segname,"_PP_BYTESVA")==0)
                data_seg = seg;
        }
        lc = (struct load_command *) ((char *)lc + lc->cmdsize);
    }
    
    if(!text_seg || !data_seg) {
        log(@"cannot parse hook info!");
        return NULL;
    }
    
    StaticInlineHookBlock* hookBlock = (StaticInlineHookBlock*)((uint64_t)header + va2rva(header, data_seg->vmaddr));
    for(int i=0; i<STATIC_HOOK_CODEPAGE_SIZE/sizeof(StaticInlineHookBlock); i++)
    {
        if(hookBlock[i].hook_vaddr == (uint64_t)vaddr)
        {
            //log(@"found hook block %d for %llX", i, vaddr);
            return &hookBlock[i];
        }
    }
    
    return NULL;
}

void* StaticInlineHookFunction(char* machoPath, uint64_t vaddr, void* replace)
{
    void* base = find_module_by_path(machoPath);
    if(!base) {
        log(@"cannot find module!");
        return NULL;
    }
    
    StaticInlineHookBlock* hookBlock = find_hook_block(base, vaddr);
    if(!hookBlock) {
        log(@"cannot find hook block!");
        return NULL;
    }
    
    hookBlock->target_replace = replace;
    return (void*)((uint64_t)base + hookBlock->original_vaddr);
}


BOOL ActiveCodePatch(char* machoPath, uint64_t vaddr, char* patch)
{
    void* base = find_module_by_path(machoPath);
    if(!base) {
        //NSLog(@"cannot find module!");
        NSLog(@"%p cannot find module!", (void *)vaddr);
        return NO;
    }
    
    StaticInlineHookBlock* hookBlock = find_hook_block(base, vaddr&~3);
    if(!hookBlock) {
        // NSLog(@"cannot find hook block!");
        NSLog(@"%p cannot find hook block!", (void *)vaddr);
        return NO;
    }
    
    if(hookBlock->patch_hash != calc_patch_hash(vaddr, patch)) {
        // NSLog(@"code patch bytes changed!");
        NSLog(@"%p code patch bytes changed!", (void *)vaddr);
        return NO;
    }
    
    hookBlock->target_replace = (void*)((uint64_t)base + hookBlock->patched_vaddr);
    
    return YES;
}

BOOL DeactiveCodePatch(char* machoPath, uint64_t vaddr, char* patch)
{
    void* base = find_module_by_path(machoPath);
    if(!base) {
        //NSLog(@"cannot find module!");
        NSLog(@"%p cannot find hook block!", (void *)vaddr);
        return NO;
    }
    
    StaticInlineHookBlock* hookBlock = find_hook_block(base, vaddr&~3);
    if(!hookBlock) {
        //NSLog(@"cannot find hook block!");
        NSLog(@"%p cannot find module!", (void *)vaddr);
        return NO;
    }
    
    if(hookBlock->patch_hash != calc_patch_hash(vaddr, patch)) {
        //NSLog(@"code patch bytes changed!");
        NSLog(@"%p code patch bytes changed!", (void *)vaddr);
        return NO;
    }
    
    hookBlock->target_replace = NULL;
    
    return YES;
}


#define kWidth  [UIScreen mainScreen].bounds.size.width
#define kHeight [UIScreen mainScreen].bounds.size.height
#define kScale [UIScreen mainScreen].scale




@interface ImGuiDrawView () <MTKViewDelegate>
@property (nonatomic, strong) id <MTLDevice> device;
@property (nonatomic, strong) id <MTLCommandQueue> commandQueue;
@end

@implementation ImGuiDrawView
  unsigned long long extraDirSize = 0;  // Khai báo biến thành viên
bool isStyle1 = false;

bool AimSkill;
int Radius = 0;
bool AutoTrung;
int skillSlot;
bool aimSkill1;
bool aimSkill2;
bool aimSkill3;
bool (*_IsSmartUse)(void *instance);
bool (*_get_IsUseCameraMoveWithIndicator)(void *instance);

bool IsSmartUse(void *instance){
    
    bool aim = false;
    
    if(skillSlot == 1 && aimSkill1){
        aim = true;
    }
    
    if(skillSlot == 2 && aimSkill2){
        aim = true;
    }
    
    if(skillSlot == 3 && aimSkill3){
        aim = true;
    }
    
    if(AutoTrung && aim){
        return true;
    }
    
    return _IsSmartUse(instance);
}


bool get_IsUseCameraMoveWithIndicator(void *instance){
    
    bool aim = false;
    
    if(skillSlot == 1 && aimSkill1){
        aim = true;
    }
    
    if(skillSlot == 2 && aimSkill2){
        aim = true;
    }
    
    if(skillSlot == 3 && aimSkill3){
        aim = true;
    }
    
    
    if(AutoTrung && aim){
        return true;
    }
    
    return _get_IsUseCameraMoveWithIndicator(instance);
}
void (*old_IsDistanceLowerEqualAsAttacker)(void *instance, int targetActor, int radius);
void IsDistanceLowerEqualAsAttacker(void *instance, int targetActor, int radius) {
    
    bool aim = false;
    
    if(skillSlot == 1 && aimSkill1){
        aim = true;
    }
    
    if(skillSlot == 2 && aimSkill2){
        aim = true;
    }
    
    if(skillSlot == 3 && aimSkill3){
        aim = true;
    }
    
    
    if (instance != NULL && AimSkill && aim) {
        radius = Radius * 1000;
    }
    old_IsDistanceLowerEqualAsAttacker(instance, targetActor, radius);
}
bool (*_IsUseSkillJoystick)(void *instance, int slot);
bool IsUseSkillJoystick(void *instance, int slot){
    skillSlot = slot;
    return _IsUseSkillJoystick(instance, slot);
}
      



float camera = 2.1;
char label[32];

float(*cam)(void* _this);
float _cam(void* _this){
return camera;{
return cam(_this);}
}

void (*highrate)(void *instance);
void _highrate(void *instance)
{
    highrate(instance);
}

static bool lockcam = false;

void (*Update)(void *instance);
void _Update(void *instance) {
  if (instance != NULL) {
    _highrate(instance);
  }
  if (lockcam) {
    return;
  }
  return Update(instance);
}


void(*loggoc)(void *instance);
void _loggoc(void *instance) {
    if(loggoc) {
        
        // [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"ngame1137://"]];
        //  exit(0);
        loggoc(instance);
    }
}


static bool AutoWinInGame = false;

void (*Autowin)(void *player, int hpPercent, int epPercent);
void _Autowin(void *player, int hpPercent, int epPercent) {
    if (player != NULL && AutoWinInGame) {
        hpPercent = -999999;
        epPercent = -999999;
    }
    Autowin(player, hpPercent, epPercent);
}

static bool isPlayerName = false; /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void (*old_SetPlayerName)(void *instance, MonoString *playerName, void *wthaxvnname, bool *isGuideLevel);
void SetPlayerName(void *instance, MonoString *playerName, void *wthaxvnname, bool *isGuideLevel) {
 if (instance != NULL && isPlayerName) {
//   wthaxvnname->setMonoString("Aov");
  playerName->setMonoString(" ");
 }
 old_SetPlayerName(instance, playerName, wthaxvnname, isGuideLevel );
}

// void (*_UpdateCooldown)(void *instance);
// void UpdateCooldown(void *instance) {
//     if (instance != NULL) {
        
        
//         uintptr_t SkillControl = AsHero(instance);
//         uintptr_t HudControl = *(uintptr_t *) ((uintptr_t)instance + 0x78);
//         if (HudControl > 0 && SkillControl > 0) {
//             uintptr_t Skill1Cd = *(int *) (SkillControl + 0x44) / 1000;
//             uintptr_t Skill2Cd = *(int *) (SkillControl + 0x64) / 1000;
//             uintptr_t Skill3Cd = *(int *) (SkillControl + 0x84) / 1000;
//             uintptr_t Skill4Cd = *(int *) (SkillControl + 0xC4) / 1000;
//             string openSk = "[";
//             string closeSk = "] ";
//             string sk1 = to_string(Skill1Cd);
//             string sk2 = to_string(Skill2Cd);
//             string sk3 = to_string(Skill3Cd);
//             string sk4 = to_string(Skill4Cd);
//             string ShowSkill = openSk + sk1 + closeSk + openSk + sk2 + closeSk + openSk + sk3 + closeSk;
//             string ShowSkill2 = openSk + sk4 + closeSk;
//             const char *str1 = ShowSkill.c_str();
//             const char *str2 = ShowSkill2.c_str();
//             if (Config.FEATMenu.showCd) {
//                 String *playerName = Tools::CreateString(str1);
//                 String *prefixName = Tools::CreateString(str2);
//                 _SetPlayerName(HudControl, playerName, prefixName, true);
//             }
//         }
//         _UpdateCooldown(instance);
//     }
// }




static bool MenDeal = true;

- (instancetype)initWithNibName:(nullable NSString *)nibNameOrNil bundle:(nullable NSBundle *)nibBundleOrNil
{
    self = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];

    _device = MTLCreateSystemDefaultDevice();
    _commandQueue = [_device newCommandQueue];

    if (!self.device) abort();

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); 
    (void)io;
    ImGui::StyleColorsClassic();

//   static const ImWchar icons_ranges[] = { 0xf000, 0xf3ff, 0 };
//     ImFontConfig icons_config;
//     ImFontConfig CustomFont;
//     CustomFont.FontDataOwnedByAtlas = false;
//     icons_config.MergeMode = true;
//     icons_config.PixelSnapH = true;
//     icons_config.OversampleH = 7;
//     icons_config.OversampleV = 7;
    io.Fonts->AddFontFromMemoryCompressedTTF((void*)font_compressed_data, font_compressed_size, 70.0f, NULL, io.Fonts->GetGlyphRangesVietnamese());
    //  io.Fonts->AddFontFromMemoryCompressedTTF(font_awesome_data, font_awesome_size, 45.0f, &icons_config, icons_ranges);
    ImGui_ImplMetal_Init(_device);

    return self;
}

+ (void)showChange:(BOOL)open
{
    MenDeal = open;
}

- (MTKView *)mtkView
{
    return (MTKView *)self.view;
}

#define HOOK(x, y, z) \
NSString* result_##y = Hello(("Frameworks/UnityFramework.framework/UnityFramework"), x, nullptr); \
if (result_##y) { \
    log(@"Hook result: %s", result_##y.UTF8String); \
    void* result = StaticInlineHookFunction(("Frameworks/UnityFramework.framework/UnityFramework"), x, (void *) y); \
    log(@"Hook result %p", result); \
    *(void **) (&z) = (void*) result; \
}

#define HOOKANOGS(x, y, z) \
NSString* result_##y = Hello(("Frameworks/anogs.framework/anogs"), x, nullptr); \
if (result_##y) { \
    log(@"Hook result: %s", result_##y.UTF8String); \
    void* result = StaticInlineHookFunction(("Frameworks/anogs.framework/anogs"), x, (void *) y); \
    log(@"Hook result %p", result); \
    *(void **) (&z) = (void*) result; \
}

- (void)loadView
{
    CGFloat w = [UIApplication sharedApplication].windows[0].rootViewController.view.frame.size.width;
    CGFloat h = [UIApplication sharedApplication].windows[0].rootViewController.view.frame.size.height;
    self.view = [[MTKView alloc] initWithFrame:CGRectMake(-80, -25, w, h)];

[self load];
}
- (void)load {
}

- (void)viewDidLoad {

    [super viewDidLoad];
    self.mtkView.device = self.device;
    self.mtkView.delegate = self;
    self.mtkView.clearColor = MTLClearColorMake(0, 0, 0, 0);
    self.mtkView.backgroundColor = [UIColor colorWithRed:0 green:0 blue:0 alpha:0];
    self.mtkView.clipsToBounds = YES;
   

//     HOOK(ENCRYPTOFFSET("0x6132140"), _cam, cam);
//     HOOK(ENCRYPTOFFSET("0x6131148"), _Update, Update);
//     HOOK(ENCRYPTOFFSET("0x6132568"), _highrate, highrate);
//     HOOK(ENCRYPTOFFSET("0x5982168"), IsSmartUse, _IsSmartUse);
//     HOOK(ENCRYPTOFFSET("0x5A43720"), get_IsUseCameraMoveWithIndicator, _get_IsUseCameraMoveWithIndicator);
//     HOOK(ENCRYPTOFFSET("0x6413310"), IsDistanceLowerEqualAsAttacker, old_IsDistanceLowerEqualAsAttacker);
//     HOOK(ENCRYPTOFFSET("0x5A45DD8"), IsUseSkillJoystick, _IsUseSkillJoystick); 
//     HOOK(ENCRYPTOFFSET("0x59DA6F4"),  SetPlayerName, old_SetPlayerName);
//     HOOK(ENCRYPTOFFSET("0x53E3100"), _Autowin, Autowin);
//     HOOK(ENCRYPTOFFSET("0x63DCA8C"), LateUpdate, old_LateUpdate);
//     HOOK(ENCRYPTOFFSET("0x5CBA408"), IsSkillDirControlRotate, old_IsSkillDirControlRotate);

//     // HOOKANOGS(ENCRYPTOFFSET("0x09AD1C"), _anogs1, anogs1);
// // HOOKANOGS(ENCRYPTOFFSET("0x132974"), anogs2, _anogs2);
// // HOOKANOGS(ENCRYPTOFFSET("0x132B54"), anogs3, _anogs3);
// // HOOKANOGS(ENCRYPTOFFSET("0x130D98"), anogs4, _anogs4);
// // HOOKANOGS(ENCRYPTOFFSET("0x191450"), anogs5, _anogs5);
// // HOOKANOGS(ENCRYPTOFFSET("0x131198"), anogs6, _anogs6);
// // HOOKANOGS(ENCRYPTOFFSET("0x19231C"), anogs7, _anogs7);
// // HOOKANOGS(ENCRYPTOFFSET("0x22CDBC"), anogs8, _anogs8);
// // HOOKANOGS(ENCRYPTOFFSET("0x131FCC"), anogs9, _anogs9);
// // HOOKANOGS(ENCRYPTOFFSET("0x1923E0"), anogs10, _anogs10);
// // HOOKANOGS(ENCRYPTOFFSET("0x22C9E8"), anogs11, _anogs11);
// // HOOKANOGS(ENCRYPTOFFSET("0x13256C"), anogs12, _anogs12);
// // HOOKANOGS(ENCRYPTOFFSET("0x192998"), anogs13, _anogs13);
// // HOOKANOGS(ENCRYPTOFFSET("0x22C114"), anogs14, _anogs14);
// // HOOKANOGS(ENCRYPTOFFSET("0x1327B4"), anogs15, _anogs15);
// // HOOKANOGS(ENCRYPTOFFSET("0x192B0C"), anogs16, _anogs16);
// // HOOKANOGS(ENCRYPTOFFSET("0x22C1E8"), anogs17, _anogs17);
// // HOOKANOGS(ENCRYPTOFFSET("0x132974"), anogs18, _anogs18);
// // HOOKANOGS(ENCRYPTOFFSET("0x1937D4"), anogs19, _anogs19);
// // HOOKANOGS(ENCRYPTOFFSET("0x22BFBC"), anogs20, _anogs20);
// // HOOKANOGS(ENCRYPTOFFSET("0x1332B8"), anogs21, _anogs21);
// // HOOKANOGS(ENCRYPTOFFSET("0x1939CC"), anogs22, _anogs22);
// // HOOKANOGS(ENCRYPTOFFSET("0x22BC00"), anogs23, _anogs23);
// // HOOKANOGS(ENCRYPTOFFSET("0x133C70"), anogs24, _anogs24);
// // HOOKANOGS(ENCRYPTOFFSET("0x193CDC"), anogs25, _anogs25);
// // HOOKANOGS(ENCRYPTOFFSET("0x22B0B4"), anogs26, _anogs26);
// // HOOKANOGS(ENCRYPTOFFSET("0x133F08"), anogs27, _anogs27);
// // HOOKANOGS(ENCRYPTOFFSET("0x193FB0"), anogs28, _anogs28);
// // HOOKANOGS(ENCRYPTOFFSET("0x22AF68"), anogs29, _anogs29);
// // HOOKANOGS(ENCRYPTOFFSET("0x1340E0"), anogs30, _anogs30);
// // HOOKANOGS(ENCRYPTOFFSET("0x194A00"), anogs31, _anogs31);
// // HOOKANOGS(ENCRYPTOFFSET("0x22AD40"), anogs32, _anogs32);
//     // HOOK(ENCRYPTOFFSET("0x622A7F8"), _AsHero, AsHero);
//     // HOOK(ENCRYPTOFFSET("0x5B40E88"), _UpdateCooldown, UpdateCooldown);

    
}

void (*set_fieldOfView)(void *camera, float value);
void *(*get_main)(void *nuls);
float drone = 0;
float defFov = 30;

void (*old_LateUpdate)(void *instance);
void LateUpdate(void *instance) {
    if (instance != NULL) {
        void *cam = get_main(NULL);
        if (cam != NULL && drone != 0) {
            set_fieldOfView(cam, (drone * 2) + defFov);
        } else {
            set_fieldOfView(cam, defFov);
        }
        old_LateUpdate(instance);
    }
}

 bool HideLine = true;
bool (*old_IsSkillDirControlRotate)(void *instance, int inSlotType);
bool IsSkillDirControlRotate(void *instance, int inSlotType) {
    if (instance != NULL && HideLine) return false;
    return old_IsSkillDirControlRotate(instance, inSlotType);
}




#pragma mark - Interaction

ImVec2 initialWindowSize = ImVec2(550, 350);

// Lưu trữ kích thước hiện tại của cửa sổ
ImVec2 currentWindowSize = initialWindowSize;

// Hệ số tăng kích thước mỗi bước
float scaleFactor = 1.2;

- (void)updateIOWithTouchEvent:(UIEvent *)event
{
    UITouch *anyTouch = event.allTouches.anyObject;
    CGPoint touchLocation = [anyTouch locationInView:self.view];
    ImGuiIO &io = ImGui::GetIO();
    io.MousePos = ImVec2(touchLocation.x, touchLocation.y);

    BOOL hasActiveTouch = NO;
    for (UITouch *touch in event.allTouches)
    {
        if (touch.phase != UITouchPhaseEnded && touch.phase != UITouchPhaseCancelled)
        {
            hasActiveTouch = YES;
            break;
        }
    }
    io.MouseDown[0] = hasActiveTouch;

    // Tăng kích thước cửa sổ nếu có di chuyển
    if (event.allTouches.count > 0) {
        // Tăng kích thước theo từng bước một
        ImVec2 nextWindowSize = ImVec2(currentWindowSize.x * scaleFactor, currentWindowSize.y * scaleFactor);
        ImGui::SetNextWindowSizeConstraints(ImVec2(550, 350), ImVec2(FLT_MAX, FLT_MAX));
        ImGui::SetNextWindowSize(nextWindowSize, ImGuiCond_Always);
        currentWindowSize = nextWindowSize;
    } else {
        // Trả lại kích thước ban đầu nếu không có sự kiện chạm
        ImGui::SetNextWindowSize(initialWindowSize, ImGuiCond_Always);
        currentWindowSize = initialWindowSize;
    }
}
- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event
{
    [self updateIOWithTouchEvent:event];
}

- (void)touchesMoved:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event
{
    [self updateIOWithTouchEvent:event];
}

- (void)touchesCancelled:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event
{
    [self updateIOWithTouchEvent:event];
}

- (void)touchesEnded:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event
{
    [self updateIOWithTouchEvent:event];
}
std::string showTime() {
    // Lấy thời gian hiện tại
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::tm* now_tm = std::localtime(&now_c);

    // Tạo định dạng giờ:phút:giây
    std::stringstream ss_time;
    ss_time << std::setw(2) << std::setfill('0') << now_tm->tm_hour << ":"
            << std::setw(2) << std::setfill('0') << now_tm->tm_min;

    return ss_time.str();
}

std::string showDate() {
    // Lấy thời gian hiện tại
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::tm* now_tm = std::localtime(&now_c);

    // Tạo định dạng thứ / ngày / tháng / năm
    std::stringstream ss_date;
    ss_date << std::setw(2) << std::setfill('0') << now_tm->tm_mday << "/"
            << std::setw(2) << std::setfill('0') << now_tm->tm_mon + 1 << "/"
            << now_tm->tm_year + 1900;

    return ss_date.str();
}
#pragma mark - MTKViewDelegat
void DrawCustomCheckbox(const char* label, bool* v)
{
    ImVec2 pos = ImGui::GetCursorScreenPos();
    ImDrawList* draw_list = ImGui::GetWindowDrawList();

    float size = ImGui::GetFrameHeight();
    ImGui::InvisibleButton(label, ImVec2(size, size));
    if (ImGui::IsItemClicked())
    {
        *v = !(*v);
    }

    // Màu nền checkbox
    ImU32 col = *v ? IM_COL32(0xcd, 0xf9, 0x00, 255) : IM_COL32(50, 50, 50, 255); // màu nền checkbox khi active và inactive
    draw_list->AddRectFilled(pos, ImVec2(pos.x + size, pos.y + size), col, 9.0f);

    // Vẽ dấu gạch ngang tùy chỉnh với góc bo tròn
    if (*v)
    {
        ImU32 dash_col = IM_COL32(0xa2, 0xc7, 0x00, 255); // màu của dấu gạch ngang
        float radius = 5.0f; // Radius góc bo tròn của dấu gạch ngang
        float dash_height = size * 0.25f; // Chiều cao của thanh ngang

        draw_list->AddRectFilled(ImVec2(pos.x + size * 0.2f, pos.y + size * 0.5f - dash_height), 
                                 ImVec2(pos.x + size * 0.8f, pos.y + size * 0.5f + dash_height), 
                                 dash_col, 
                                 radius);
    }

    ImGui::SameLine();
    ImGui::Text(label);
}

void DrawTextWithScaleAndColor(const char* label, const char* text, float fontScale)
{
    ImGui::TextColored(ImColor(255 / 255.0f, 255 / 255.0f, 255 / 255.0f), label);
    ImGui::SetWindowFontScale(fontScale);
    ImGui::TextColored(ImColor(150 / 255.0f, 150 / 255.0f, 150 / 255.0f), text);
    ImGui::SetWindowFontScale(0.67f); // Reset font scale to default
}
// Khai báo biến toàn cục
static float extraButtonWidth = 165.0f;
static float toolsButtonWidth = 165.0f;
static float visibleButtonWidth = 165.0f;
static float animationProgress[3] = {0.0f, 0.0f, 0.0f};
static bool isAnimating[3] = {false, false, false};

// Hằng số cho kích thước nút và khoảng cách
const float BUTTON_WIDTH = 165.0f;
const float BUTTON_HEIGHT = 38.0f;
const float ICON_WIDTH = 38.0f;
const float BUTTON_SPACING = 5.0f;
const float ANIMATION_SPEED = 8.0f;

// Hàm AnimateButton (giữ nguyên từ mã gốc của bạn)
void AnimateButton(int index, bool isActive, float& buttonWidth) {
    if (isActive && !isAnimating[index]) {
        isAnimating[index] = true;
        animationProgress[index] = 0.0f;
    }
    else if (!isActive && isAnimating[index]) {
        isAnimating[index] = false;
        animationProgress[index] = 0.0f;
    }
    if (isAnimating[index]) {
        animationProgress[index] += ImGui::GetIO().DeltaTime * ANIMATION_SPEED;
        if (animationProgress[index] > 1.0f) animationProgress[index] = 1.0f;
        buttonWidth = BUTTON_WIDTH - (45.0f * animationProgress[index]);
    }
    else {
        buttonWidth = isActive ? 110.0f : BUTTON_WIDTH;
    }
}

// Hàm để xử lý hoạt ảnh và vẽ nút
void VeNutHoatAnh(const char* nhanNut, const char* bieuTuong, int index, bool kichHoat, ImVec2 viTri) {
    float& buttonWidth = index == 0 ? extraButtonWidth : (index == 1 ? toolsButtonWidth : visibleButtonWidth);
    
    AnimateButton(index, kichHoat, buttonWidth);
    
    ImGui::SetCursorPos(viTri);
    
    ImGui::PushStyleColor(ImGuiCol_Text, kichHoat ? ImVec4(0, 0, 0, 1.0f) : ImVec4(200 / 255.0f, 200 / 255.0f, 200 / 255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Button, kichHoat ? ImVec4(205 / 255.0f, 250 / 255.0f, 0 / 255.0f, 1.0f) : ImVec4(24 / 255.0f, 24 / 255.0f, 24 / 255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(205 / 255.0f, 250 / 255.0f, 0 / 255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(205 / 255.0f, 250 / 255.0f, 0 / 255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Border, kichHoat ? ImVec4(127 / 255.0f, 157 / 255.0f, 0 / 255.0f, 1.0f) : ImVec4(120 / 255.0f, 120 / 255.0f, 120 / 255.0f, 1.0f));
    
    if (ImGui::Button(nhanNut, ImVec2(buttonWidth, BUTTON_HEIGHT))) {
        Settings::Tab = index + 2;
        isAnimating[index] = true;
        animationProgress[index] = 0.0f;
    }
    
    if (kichHoat || isAnimating[index]) {
        ImGui::SetCursorPos(ImVec2(viTri.x + buttonWidth + 6, viTri.y));
        ImGui::SetWindowFontScale(1.5f);
          ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(127 / 255.0f, 157 / 255.0f, 0 / 255.0f, 1.0f));
        ImGui::Button(bieuTuong, ImVec2(ICON_WIDTH, BUTTON_HEIGHT));
          ImGui::PopStyleColor(1);
        ImGui::SetWindowFontScale(0.8f);
    }
    
    ImGui::PopStyleColor(5);
}
ImVec4 ImLerp(const ImVec4& a, const ImVec4& b, float t)
{
    return ImVec4(
        a.x + (b.x - a.x) * t,
        a.y + (b.y - a.y) * t,
        a.z + (b.z - a.z) * t,
        a.w + (b.w - a.w) * t
    );
}

void TriggerHapticFeedback() {
  if (@available(iOS 10.0, *)) {
    UIImpactFeedbackGenerator *generator = [[UIImpactFeedbackGenerator alloc]
        initWithStyle:UIImpactFeedbackStyleLight];
    [generator prepare];
    [generator impactOccurred];
  }
}
ImVec4 SetAlpha(const ImVec4& color, float alpha) {
    return ImVec4(color.x, color.y, color.z, alpha);
}

// Variables to track button heights, text alphas, and font scales
static float moreButtonHeight = 70.0f;
static float infoButtonHeight = 70.0f;
static float moreTextAlpha = 0.0f;
static float infoTextAlpha = 0.0f;
static float moreTextScale = 0.18f;
static float infoTextScale = 0.18f;

// Function to gradually change button height
float AdjustButtonHeight(float& currentHeight, bool isActive) {
    float targetHeight = isActive ? 55.0f : 70.0f;
    if (currentHeight != targetHeight) {
        currentHeight += (targetHeight > currentHeight) ? 2.5f : -2.5f;
    }
    return currentHeight;
}

// Function to gradually change text alpha
float AdjustTextAlpha(float& currentAlpha, bool isActive) {
    float targetAlpha = isActive ? 1.0f : 0.0f;
    if (currentAlpha != targetAlpha) {
        currentAlpha += (targetAlpha > currentAlpha) ? 0.2f : -0.2f;
        currentAlpha = std::max(0.0f, std::min(1.0f, currentAlpha)); // Clamp between 0 and 1
    }
    return currentAlpha;
}

// Function to gradually change font scale
float AdjustFontScale(float& currentScale, bool isActive) {
    float targetScale = isActive ? 0.58f : 0.18f;
    if (currentScale != targetScale) {
        currentScale += (targetScale > currentScale) ? 0.04f : -0.04f;
        currentScale = std::max(0.18f, std::min(0.58f, currentScale)); // Clamp between 0.18 and 0.58
    }
    return currentScale;
}

bool IsInRange(float value, float min, float max) {
    return value >= min && value < max;
}

// Hàm để đặt màu cho nút dựa trên khoảng giá trị
void SetButtonColorIfInRange(const char* label, float minValue, float maxValue, float sliderValue, ImVec2 size, float setValue) {
    bool isInRange = IsInRange(sliderValue, minValue, maxValue);
    bool shouldBeGreen = false;

    // Check if this button or any higher value buttons should be green
    if (setValue <= 1.2f && sliderValue >= 1.2f) shouldBeGreen = true;
    else if (setValue <= 1.65f && sliderValue >= 1.65f) shouldBeGreen = true;
    else if (setValue <= 2.1f && sliderValue >= 2.1f) shouldBeGreen = true;
    else if (setValue <= 2.7f && sliderValue >= 2.7f) shouldBeGreen = true;

    if (isInRange || shouldBeGreen) {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.80f, 1.0f, 0.0f, 1.0f)); // RGB: 205, 255, 0
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.80f, 1.0f, 0.0f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.80f, 1.0f, 0.0f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0f, 0.0f, 0.0f, 1.0f)); // Black text
    }

    if (ImGui::Button(label, size)) {
        // Xử lý sự kiện khi nút được nhấn
        camera = setValue;
    }

    if (isInRange || shouldBeGreen) {
        ImGui::PopStyleColor(4);
    }
}

void AddUnderLine(ImColor col_)
{
    ImVec2 min = ImGui::GetItemRectMin();
    ImVec2 max = ImGui::GetItemRectMax();
    min.y = max.y;
    ImGui::GetWindowDrawList()->AddLine(min, max, col_, 1.0f);
}

void OpenURLiOS(const char* url) {
    @autoreleasepool {
        NSString* nsUrl = [NSString stringWithUTF8String:url];
        NSURL* URL = [NSURL URLWithString:nsUrl];
        if ([[UIApplication sharedApplication] canOpenURL:URL]) {
            [[UIApplication sharedApplication] openURL:URL options:@{} completionHandler:nil];
        } else {
            NSLog(@"Cannot open URL: %@", nsUrl);
        }
    }
}

void ImGuiTextURL(const char* name, const char* URL, bool sameLineBefore = false, bool sameLineAfter = false) {
    if (sameLineBefore) {

        ImGui::SetWindowFontScale(0.67f);
        ImGui::SameLine(0.0f, ImGui::GetStyle().ItemInnerSpacing.x);
    }
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.757f, 0.0f, 1.0f));
    ImGui::Text("%s", name);  // Removed OBFUSCATE macro
    ImGui::PopStyleColor();

    if (ImGui::IsItemHovered()) {
        if (ImGui::IsMouseClicked(0)) {
            OpenURLiOS(URL);  // Use our new wrapper function
        }
        
        AddUnderLine(ImColor(1.0f, 0.757f, 0.0f, 1.0f));
        // ImGui::SetTooltip("( Visit Me At\n%s", URL);  // Removed ICON_FA_LINK
    } else {
        AddUnderLine(ImColor(1.0f, 0.757f, 0.0f, 1.0f));
    }
    if (sameLineAfter) {
        ImGui::SameLine(0.0f, ImGui::GetStyle().ItemInnerSpacing.x);
    }
}

void openURL(const char* url) {
    NSString *urlString = [NSString stringWithUTF8String:url];
    NSURL *nsurl = [NSURL URLWithString:urlString];
    dispatch_async(dispatch_get_main_queue(), ^{
        [[UIApplication sharedApplication] openURL:nsurl options:@{} completionHandler:nil];
    });
}

void RenderZaloGroupButton(const char* url) {
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 20.0f);
    
    ImVec2 buttonSize(90, 90);
    ImVec2 textPadding(5, 5);
    
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1.0f/255.0f, 113.0f/255.0f, 227.0f/255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f/255.0f, 113.0f/255.0f, 227.0f/255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1.0f/255.0f, 113.0f/255.0f, 227.0f/255.0f, 1.0f));
    
    if (ImGui::Button("##ZaloGroup", buttonSize)) {
        // Khi nút được nhấn, mở URL
        #ifdef __APPLE__
            [[UIApplication sharedApplication] openURL:[NSURL URLWithString:[NSString stringWithUTF8String:url]]];
        #endif
    }
    
    ImGui::PopStyleColor(3);
    
    ImVec2 buttonPos = ImGui::GetItemRectMin();
    ImDrawList* drawList = ImGui::GetWindowDrawList();
    
    // Vẽ dòng chữ "ZALO GROUP"
    ImGui::SetWindowFontScale(1.0f);
     // Vẽ dòng chữ "ZALO GROUP" (đã xích xuống 10px)
    drawList->AddText(ImVec2(buttonPos.x + textPadding.x, buttonPos.y + textPadding.y + 6), 
                      IM_COL32(255, 255, 255, 255), " ZALO");
                          
    drawList->AddText(ImVec2(buttonPos.x + textPadding.x, buttonPos.y + textPadding.y + 23), 
                      IM_COL32(255, 255, 255, 255), " GROUP");
    
    
    // Vẽ dòng chữ "HỘI NHỮNG NGƯỜI THÍCH ĐI TÙ"
    ImGui::SetWindowFontScale(0.5f);
    ImVec2 textSize = ImGui::CalcTextSize(" HỘI NHỮNG\n NGƯỜI\n THÍCH ĐI TÙ");
  drawList->AddText(ImVec2(buttonPos.x + textPadding.x, 
                             buttonPos.y + buttonSize.y - textSize.y - textPadding.y - 3), 
                      IM_COL32(255, 255, 255, 255), " HỘI NHỮNG\n NGƯỜI\n THÍCH ĐI TÙ");
    
    ImGui::PopStyleVar();
}


void RenderFBButton(const char* url) {
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 15.0f);
    
    ImVec2 buttonSize(156, 42);
    ImVec2 textPadding(5, 5);
    
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1.0f/255.0f, 113.0f/255.0f, 227.0f/255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f/255.0f, 113.0f/255.0f, 227.0f/255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1.0f/255.0f, 113.0f/255.0f, 227.0f/255.0f, 1.0f));
    
    if (ImGui::Button("##FBGroup", buttonSize)) {
        // Khi nút được nhấn, mở URL
        #ifdef __APPLE__
            [[UIApplication sharedApplication] openURL:[NSURL URLWithString:[NSString stringWithUTF8String:url]]];
        #endif
    }
    
    ImGui::PopStyleColor(3);
    
    ImVec2 buttonPos = ImGui::GetItemRectMin();
    ImDrawList* drawList = ImGui::GetWindowDrawList();
    
    // Vẽ dòng chữ "ZALO GROUP"
    ImGui::SetWindowFontScale(1.0f);
     // Vẽ dòng chữ "ZALO GROUP" (đã xích xuống 10px)
    drawList->AddText(ImVec2(buttonPos.x + textPadding.x, buttonPos.y + textPadding.y + 5), 
                      IM_COL32(255, 255, 255, 255), " NGUYỄN THIỆN");
    
    // Vẽ dòng chữ "HỘI NHỮNG NGƯỜI THÍCH ĐI TÙ"
    ImGui::SetWindowFontScale(0.5f);
    ImVec2 textSize = ImGui::CalcTextSize(" PERSONAL ACCOUNT");
  drawList->AddText(ImVec2(buttonPos.x + textPadding.x, 
                             buttonPos.y + buttonSize.y - textSize.y - textPadding.y - 0), 
                      IM_COL32(255, 255, 255, 255), "  PERSONAL ACCOUNT");
    
    ImGui::PopStyleVar();
}

void RenderMOMOButton(const char* url) {
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 15.0f);
    
    ImVec2 buttonSize(95, 42);
    ImVec2 textPadding(5, 5);
    
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(255.0f/255.0f, 204.0f/255.0f, 255.0f/255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(255.0f/255.0f, 204.0f/255.0f, 255.0f/255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(255.0f/255.0f, 204.0f/255.0f, 255.0f/255.0f, 1.0f));
    
    if (ImGui::Button("##MOMOGroup", buttonSize)) {
        // Khi nút được nhấn, mở URL
        #ifdef __APPLE__
            [[UIApplication sharedApplication] openURL:[NSURL URLWithString:[NSString stringWithUTF8String:url]]];
        #endif
    }
    
    ImGui::PopStyleColor(3);
    
    ImVec2 buttonPos = ImGui::GetItemRectMin();
    ImDrawList* drawList = ImGui::GetWindowDrawList();
    

     ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(168.0f/255.0f, 5.0f/255.0f, 102.0f/255.0f, 1.0f));
    // Vẽ dòng chữ "ZALO GROUP"
    ImGui::SetWindowFontScale(0.6f);
     // Vẽ dòng chữ "ZALO GROUP" (đã xích xuống 10px)
    drawList->AddText(ImVec2(buttonPos.x + textPadding.x, buttonPos.y + textPadding.y + 1), 
                      IM_COL32(168, 5, 102, 255), "   DONATE ME");
    
    // Vẽ dòng chữ "HỘI NHỮNG NGƯỜI THÍCH ĐI TÙ"
    ImGui::SetWindowFontScale(1.2f);
    ImVec2 textSize = ImGui::CalcTextSize(" MOMO");
  drawList->AddText(ImVec2(buttonPos.x + textPadding.x, 
                             buttonPos.y + buttonSize.y - textSize.y - textPadding.y - 0), 
                      IM_COL32(168, 5, 102, 255), " MOMO");
     ImGui::PopStyleColor();
    ImGui::PopStyleVar();
}



void RenderBIOButton(const char* url) {
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 15.0f);
    
    ImVec2 buttonSize(262-5, 42);
    ImVec2 textPadding(5, 5);
    
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(205.0f/255.0f, 255.0f/255.0f, 0.0f/255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(205.0f/255.0f, 255.0f/255.0f, 0.0f/255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(205.0f/255.0f, 255.0f/255.0f, 0.0f/255.0f, 1.0f));
   

    if (ImGui::Button("##BIOGroup", buttonSize)) {
        // Khi nút được nhấn, mở URL
        #ifdef __APPLE__
            [[UIApplication sharedApplication] openURL:[NSURL URLWithString:[NSString stringWithUTF8String:url]]];
        #endif
    }
    
    ImGui::PopStyleColor(3);
    
    ImVec2 buttonPos = ImGui::GetItemRectMin();
    ImDrawList* drawList = ImGui::GetWindowDrawList();
    
    // Vẽ dòng chữ "ZALO GROUP"
     ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f/255.0f, 1.0f/255.0f, 1.0f/255.0f, 1.0f));
    ImGui::SetWindowFontScale(0.6f);
     // Vẽ dòng chữ "ZALO GROUP" (đã xích xuống 10px)
    drawList->AddText(ImVec2(buttonPos.x + textPadding.x, buttonPos.y + textPadding.y + 1), 
                      IM_COL32(1, 1, 1, 255), "  MY BIO LINK - UPDATE YOUR HACK");
    
    // Vẽ dòng chữ "HỘI NHỮNG NGƯỜI THÍCH ĐI TÙ"
    ImGui::SetWindowFontScale(1.0f);
    ImVec2 textSize = ImGui::CalcTextSize("  BENTO.ME/WTHAXVN");
  drawList->AddText(ImVec2(buttonPos.x + textPadding.x, 
                             buttonPos.y + buttonSize.y - textSize.y - textPadding.y - 1), 
                      IM_COL32(1, 1, 1, 255), " BENTO.ME/WTHAXVN");
     ImGui::PopStyleColor();
    ImGui::PopStyleVar();
}


    float lerp(float a, float b, float t) {
    return a + t * (b - a);
}


- (void)drawInMTKView:(MTKView*)view
{
   
    
    ImGuiIO& io = ImGui::GetIO();
    io.DisplaySize.x = view.bounds.size.width;
    io.DisplaySize.y = view.bounds.size.height;

    CGFloat framebufferScale = view.window.screen.scale ?: UIScreen.mainScreen.scale;
    io.DisplayFramebufferScale = ImVec2(framebufferScale, framebufferScale);
    io.DeltaTime = 1 / float(view.preferredFramesPerSecond ?: 120);
    
    id<MTLCommandBuffer> commandBuffer = [self.commandQueue commandBuffer];

    static float windowBgAlpha = 1.0f;
    static int selectedStyleIndex = false;
    static bool onehit = false;   
    static bool skill0s = false; 
    static bool hackmap = false;
    static bool camxa = false; 
    static bool hidename = false;
    static bool hoichieu = false;
    static bool fullskin = false;   
    static bool balo = false;   
    static bool uid = false;  
//Define active function
    static bool fullskin_active = false;
    static bool balo_active = false;
    static bool uid_active = false;
    static bool onehit_active = false;
    static bool skill0s_active = false;
    static bool hidename_active = false;
    static bool hackmap_active = false;
    static bool xoay_active = false; 
    static bool ghim_active = false;
    static bool hoichieu_active = false;

//Define your bool/function in here 
    static bool antiban = false;
    static bool map = false; 
    static bool skillcd = false; 

    static bool map_active = false;
    static bool antiban_active = false;
    static bool skill_active = false;
    
    
        
        if (MenDeal == true) {
            [self.view setUserInteractionEnabled:YES];
        } else if (MenDeal == false) {
            [self.view setUserInteractionEnabled:NO];
        
            
            
        }

        MTLRenderPassDescriptor* renderPassDescriptor = view.currentRenderPassDescriptor;
        if (renderPassDescriptor != nil)
        {
            id <MTLRenderCommandEncoder> renderEncoder = [commandBuffer renderCommandEncoderWithDescriptor:renderPassDescriptor];
            [renderEncoder pushDebugGroup:@"ImGui Jane"];

            ImGui_ImplMetal_NewFrame(renderPassDescriptor);
            ImGui::NewFrame();
            
            //  ImFont* font = ImGui::GetFont();
            // font->Scale = 24.0f / font->FontSize; //BEAUS

            ImFont* font = ImGui::GetFont();
            font->Scale = 19.0f / font->FontSize; //RUBIK
            
            CGFloat x = (([UIApplication sharedApplication].windows[0].rootViewController.view.frame.size.width) - 360) / 2;
            CGFloat y = (([UIApplication sharedApplication].windows[0].rootViewController.view.frame.size.height) - 300) / 2;
            
            ImGui::SetNextWindowPos(ImVec2(x, y), ImGuiCond_FirstUseEver);
            ImGui::SetNextWindowSize(ImVec2(500, 350), ImGuiCond_FirstUseEver);
            
            if (MenDeal == true)
            {             std::string namedv = [[UIDevice currentDevice] name].UTF8String;
            NSDate *now = [NSDate date];
            NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
            [dateFormatter setDateFormat:@"EEEE dd/MM/yyyy"];
            NSString *dateString = [dateFormatter stringFromDate:now];

            UIDevice *device = [UIDevice currentDevice];
            device.batteryMonitoringEnabled = YES;

            float batteryLevel = device.batteryLevel * 100;
            NSString *chargingStatus = @"";
            if (device.batteryState == UIDeviceBatteryStateCharging) {
                chargingStatus = @"- Đang Sạc";
            } else if (device.batteryState == UIDeviceBatteryStateFull) {
                chargingStatus = @"- Đầy Pin";
            } else {
                chargingStatus = @"- Đã Ngắt Sạc";
            }

            int numCores;
            size_t len = sizeof(numCores);
            sysctlbyname("hw.ncpu", &numCores, &len, NULL, 0);

          kern_return_t kr;
          task_info_data_t tinfo;
          mach_msg_type_number_t task_info_count = TASK_INFO_MAX;
          
          kr = task_info(mach_task_self(),
                         TASK_BASIC_INFO,
                         (task_info_t)tinfo,
                         &task_info_count);
          if (kr != KERN_SUCCESS) {
            return;
          }

          task_basic_info_t      basic_info;
          thread_array_t         thread_list;
          mach_msg_type_number_t thread_count;
          
          thread_info_data_t     thinfo;
          mach_msg_type_number_t thread_info_count;

          basic_info = (task_basic_info_t)tinfo;
          
          // Calculate RAM usage
          natural_t used_ram = (basic_info->resident_size) / 1024 / 1024;
          // Calculate available RAM
          natural_t free_ram = ([NSProcessInfo processInfo].physicalMemory) / 1024 / 1024 - used_ram;
          char used_ram_str[100];
          char free_ram_str[100];
          
          ImVec4 used_color = ImVec4(0.5f, 0, 0.5f, 1);
          ImVec4 ram_color = ImVec4(1, 1, 0, 1);

        long num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
        long page_size = sysconf(_SC_PAGESIZE);
        long num_pages = sysconf(_SC_PHYS_PAGES);
        long ram_total = num_pages * page_size; 
                ImGui::Begin(ENCRYPT( "= WtHaxVN | ImGui NonJB V2.0"), &MenDeal,  ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoScrollbar);
 ImVec2 windowPos = ImGui::GetWindowPos();
ImVec2 windowSize = ImGui::GetWindowSize();
float rectWidth = windowSize.x * 0.8f;  // 80% of the window width
float rectHeight = 50.0f;               // Height of 50 pixels as requested
float rectX = windowPos.x + (windowSize.x - rectWidth) / 2.0f; // Center horizontally
float rectY = windowPos.y;

float cornerRadius = 20.0f; // Set corner radius for all corners

// Define the colors for the gradient
ImU32 colorLeft = IM_COL32(82, 100, 13, 255);  // Left color (RGB: 82, 100, 0)
ImU32 colorTopLeft = IM_COL32(82, 100, 13, 255);  // Top-left color (RGB: 82, 100, 0)
ImU32 colorTopRight = IM_COL32(15, 19, 20, 255);  // Top-right color (RGB: 15, 19, 20)
ImU32 colorRight = IM_COL32(15, 19, 20, 255);  // Right color (RGB: 15, 19, 20)
ImU32 colorBottomRight = IM_COL32(15, 19, 20, 255);  // Bottom-right color (RGB: 15, 19, 20)
ImU32 colorBottomLeft = IM_COL32(82, 100, 13, 255);  // Bottom-left color (RGB: 82, 100, 0)

// Draw the rectangle with a gradient and rounded corners
ImGui::GetWindowDrawList()->AddRectFilledMultiColor(
    ImVec2(rectX, rectY),
    ImVec2(rectX + rectWidth, rectY + rectHeight),
    colorTopLeft, colorTopRight, colorBottomRight, colorBottomLeft
);
ImGui::SetWindowFontScale(1.5f); 

// Static variables to store previous tab and animation state
static int previousTab = -1;
static float animProgress = 1.0f;
static float animDuration = 0.25f; // Animation duration in seconds
static std::string currentText = "AOV | [ VN 1.55 ] S3 2024";
static std::unordered_map<int, std::string> tabTexts = {
    {1, "HOME"},
    {2, "EXTRA"},
    {3, "TOOLS"},
    {4, "OTHER"},
    {5, "NOTIFICATION"},
    {6, "ABOUT AUTHOR"},
    {7, "INFO"}
};

// Start the animation if the tab changed
if (Settings::Tab != previousTab) {
    previousTab = Settings::Tab;
    animProgress = 0.0f;
}

// Handle the animation
bool animating = (animProgress < 1.0f);
if (animating) {
    animProgress += ImGui::GetIO().DeltaTime / animDuration;
    if (animProgress >= 1.0f) {
        animProgress = 1.0f;
        currentText = tabTexts.count(Settings::Tab) ? tabTexts[Settings::Tab] : "AOV | [ VN 1.55 ] S3 2024";
    }
}

// Calculate text positions
float oldTextAlpha = 1.0f - animProgress;
float newTextAlpha = animProgress;
float oldTextOffsetX = 17.0f * animProgress;
float newTextOffsetX = 17.0f * (1.0f - animProgress);

// Move the text cluster to the right by 60 pixels
rectX += 10.0f;

// Render the old text (fading out and moving right)
ImGui::SetCursorPos(ImVec2(rectX + 25 + oldTextOffsetX - windowPos.x, rectY + 15 - windowPos.y));
ImGui::PushStyleVar(ImGuiStyleVar_Alpha, oldTextAlpha);
ImGui::TextColored(ImVec4(1.0f, 1.0f, 1.0f, oldTextAlpha), "%s", currentText.c_str());
ImGui::PopStyleVar();

// Render the new text (fading in and moving left)
std::string newText = tabTexts.count(Settings::Tab) ? tabTexts[Settings::Tab] : "AOV | [ VN 1.55 ] S3 2024";
ImGui::SetCursorPos(ImVec2(rectX + 25 + newTextOffsetX - windowPos.x, rectY + 15 - windowPos.y));
ImGui::PushStyleVar(ImGuiStyleVar_Alpha, newTextAlpha);
ImGui::TextColored(ImVec4(1.0f, 1.0f, 1.0f, newTextAlpha), "%s", newText.c_str());
ImGui::PopStyleVar();

float buttonSize = 30.0f;
float buttonX = rectX + rectWidth - buttonSize - 10 - 70; // 5 pixels từ cạnh phải
float buttonY = rectY + 15; // 5 pixels từ cạnh trên
ImGui::SetCursorPos(ImVec2(buttonX - windowPos.x, buttonY - windowPos.y));


ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(205.0f / 255.0f, 250.0f / 255.0f, 0.0f / 255.0f, 0.0f));
ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1 / 255.0f, 113 / 255.0f, 227 / 255.0f, 0.0f));
ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1 / 255.0f, 113 / 255.0f, 227 / 255.0f, 0.0f));
ImGui::SetWindowFontScale(1.35f); // Tăng kích thước font cho header

ImGui::PushStyleColor(ImGuiCol_Text, Settings::Tab == 7 ? ImVec4(205 / 255.0f, 250 / 255.0f, 0 / 255.0f, 1.0f) : ImVec4(255 / 255.0f, 255 / 255.0f, 255 / 255.0f, 1.0f));
if (ImGui::Button(";", ImVec2(buttonSize, buttonSize))) {
    Settings::Tab = 7;
}
ImGui::PopStyleColor();
ImGui::SameLine();
ImGui::Dummy(ImVec2(5, 0)); // Khoảng cách 5px
ImGui::SameLine();

static bool circleGray = false; // Biến static để theo dõi trạng thái màu của vòng tròn

ImGui::PushStyleColor(ImGuiCol_Text, Settings::Tab == 5 ? ImVec4(205 / 255.0f, 250 / 255.0f, 0 / 255.0f, 1.0f) : ImVec4(255 / 255.0f, 255 / 255.0f, 255 / 255.0f, 1.0f));

if (ImGui::Button("+", ImVec2(buttonSize, buttonSize))) {
    Settings::Tab = 5;
    circleGray = true; // Chuyển vòng tròn sang màu xám khi nút "+" được nhấn
}
ImGui::PopStyleColor();

ImGui::SameLine();
ImGui::Dummy(ImVec2(5, 0)); // Khoảng cách 5px
ImGui::SameLine();

ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(255 / 255.0f, 255 / 255.0f, 255 / 255.0f, 1.0f));

if (ImGui::Button("`", ImVec2(buttonSize, buttonSize))) {
    MenDeal = false;
}
ImGui::PopStyleColor();
ImGui::PopStyleColor(3);

// Vẽ vòng tròn với viền đen phía trên nút "+"
float circleRadius = 6.0f;
ImVec2 circleCenter(buttonX + buttonSize / 2 + 60.0f, buttonY - 15.0f + 20.0f);

// Vẽ viền đen (độ dày 2px)
ImGui::GetWindowDrawList()->AddCircle(circleCenter, circleRadius + 1.0f, IM_COL32(0, 0, 0, 255), 0, 4.0f);

// Vẽ vòng tròn với màu dựa trên trạng thái
ImU32 circleColor = circleGray ? IM_COL32(128, 128, 128, 255) : IM_COL32(255, 0, 0, 255);
ImGui::GetWindowDrawList()->AddCircleFilled(circleCenter, circleRadius, circleColor);
// Draw the red circle with a black border above the "+" button


ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12, 8)); // Adjust the padding to set the height
ImGui::SetCursorPos(ImVec2(500, 48));
ImGui::Columns(2);
ImGui::SetColumnOffset(1, 80);

// CỘT BÊN TRÁI
{

static float indicatorY = 70.0f;
static int __unused activeButton = 0;

ImVec2 windowPos = ImGui::GetWindowPos();
ImVec2 windowSize = ImGui::GetWindowSize();
float rectWidth = 75.0f;
float rectHeight = 350.0f;
float rectX = windowPos.x;
float rectY = windowPos.y + windowSize.y - rectHeight;
float cornerRadius = 25.0f;

// Draw the black rectangle with rounded top-left and bottom-left corners
ImGui::GetWindowDrawList()->AddRectFilled(
    ImVec2(rectX, rectY),
    ImVec2(rectX + rectWidth, rectY + rectHeight),
    IM_COL32(23, 27, 30, 255),
    cornerRadius,
    ImDrawFlags_RoundCornersTopLeft | ImDrawFlags_RoundCornersBottomLeft
);

// Smooth animation for indicator movement
static float targetIndicatorY = indicatorY;
targetIndicatorY = lerp(targetIndicatorY, indicatorY, ImGui::GetIO().DeltaTime * 10.0f);

// Draw the green indicator rectangle

ImColor activeColor = IM_COL32(205, 250, 0, 255);  // Bright green for tabs 1-4
ImColor inactiveColor = IM_COL32(125, 150, 0, 255);  // Darker green for tabs 5-7

// Determine the color based on Settings::Tab
ImColor indicatorColor = (Settings::Tab >= 1 && Settings::Tab <= 4) ? activeColor : inactiveColor;

// Draw the green indicator rectangle
float indicatorWidth = 3.0f;
float indicatorHeight = 50.0f;
float indicatorX = rectX + rectWidth - indicatorWidth;
ImGui::GetWindowDrawList()->AddRectFilled(
    ImVec2(indicatorX, rectY + targetIndicatorY),
    ImVec2(indicatorX + indicatorWidth, rectY + targetIndicatorY + indicatorHeight),
    indicatorColor
);

// Configure button style
ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(23.0f/255.0f, 27.0f/255.0f, 30.0f/255.0f, 0.0f));
ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(23.0f/255.0f, 27.0f/255.0f, 30.0f/255.0f, 0.0f));
ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(23.0f/255.0f, 27.0f/255.0f, 30.0f/255.0f, 0.0f));
ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(150.0f/255.0f, 150.0f/255.0f, 150.0f/255.0f, 1.0f)); // Default text color

// Set button size
ImGui::PushStyleVar(ImGuiStyleVar_ButtonTextAlign, ImVec2(0.5f, 0.5f));
ImVec2 buttonSize(65.0f, 50.0f);

// Function to create a button with conditional active state
auto CreateButton = [&](const char* label, int buttonIndex, float yOffset, int tabValue) {
    if (Settings::Tab == tabValue) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f)); // White text for active button
    }
    bool clicked = ImGui::Button(label, buttonSize);
    if (Settings::Tab == tabValue) {
        ImGui::PopStyleColor();
    }
    if (clicked) {
        Settings::Tab = tabValue;
        activeButton = buttonIndex;
        indicatorY = 70.0f + buttonIndex * 54.0f;
    }
};

// Create buttons
ImGui::SetWindowFontScale(1.5f);
ImGui::Spacing();
ImGui::Spacing();
ImGui::Spacing();
ImGui::Spacing();
ImGui::Spacing();
ImGui::Spacing();
CreateButton("*", 0, 0.0f, 1); // Settings::Tab = 1
CreateButton("@", 1, 60.0f, 2); // Settings::Tab = 2
CreateButton("}", 2, 120.0f, 3); // Settings::Tab = 3
CreateButton("^", 3, 180.0f, 4); // Settings::Tab = 4

// Reset style
ImGui::PopStyleVar();
ImGui::PopStyleColor(4);

// Add "$" text to the top-left corner
ImGui::SetWindowFontScale(1.0f);
ImGui::SetCursorPos(ImVec2(19, 50));
ImGui::TextColored(ImColor(205 / 255.0f,249 / 255.0f, 0 / 255.0f), ":");

ImVec2 window_pos = ImGui::GetWindowPos();
ImVec2 window_size = ImGui::GetWindowSize();
float window_bottom = window_pos.y + window_size.y;

// Tính toán vị trí của hình chữ nhật
float margin_left = 10.0f;
float margin_bottom =10.0f;
float corner_radius = 18.0f;
ImVec2 rect_pos(window_pos.x + margin_left, window_bottom - margin_bottom - 50); // Cách lề trái 15px, cách đáy 5px, cao 60px

// Vẽ hình chữ nhật
ImVec2 rect_size(60, 50);
ImDrawList* draw_list = ImGui::GetWindowDrawList();
draw_list->AddRectFilled(rect_pos, ImVec2(rect_pos.x + rect_size.x, rect_pos.y + rect_size.y),
                         IM_COL32(43, 47, 50, 255), corner_radius, ImDrawCornerFlags_All);

                      

// Đặt vị trí vẽ ở góc trái dưới cùng của cửa sổ
// ImVec2 window_pos = ImGui::GetWindowPos();
// ImVec2 window_size = ImGui::GetWindowSize();

ImVec2 cursor_pos(window_pos.x + 20, window_pos.y + window_size.y - 50); // Cách lề trái 15 đơn vị và cách đáy 40 đơn vị

ImGui::SetCursorPos(ImVec2(22, ImGui::GetWindowSize().y - 51));
 ImGui::SetWindowFontScale(2.0f); 
ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(43 / 255.0f, 47 / 255.0f, 50 / 255.0f, 0.0f));
ImGui::PushStyleColor(ImGuiCol_HeaderActive, ImVec4(43 / 255.0f, 47 / 255.0f, 50 / 255.0f, 0.0f));

ImGui::PushStyleColor(ImGuiCol_Text, Settings::Tab == 6 ? ImVec4(205 / 255.0f, 250 / 255.0f, 0 / 255.0f, 1.0f) : ImVec4(255 / 255.0f, 255 / 255.0f, 255 / 255.0f, 1.0f));
if (ImGui::Selectable("=", false, ImGuiSelectableFlags_None)) {
    // Thực hiện hành động khi chọn vào "NguyenThien" ở đây
    Settings::Tab = 6;
}

ImGui::PopStyleColor(3);
ImGui::SameLine();

time_t now = time(0);
tm *ltm = localtime(&now);
int hour = ltm->tm_hour;
int min = ltm->tm_min;

ImVec4 circleColor;

if ((hour >= 8 && hour < 11) || (hour == 11 && min < 55)) {
    circleColor = ImVec4(0.0f, 1.0f, 0.0f, 1.0f); // Màu xanh lá từ 8:00 đến 11:54
} else if ((hour == 11 && min >= 55) || (hour == 12 && min <= 30)) {
    circleColor = ImVec4(1.0f, 0.0f, 0.0f, 1.0f); // Màu đỏ từ 11:55 đến 12:30
} else if ((hour == 12 && min > 30) || (hour == 13 && min < 35)) {
    circleColor = ImVec4(0.0f, 1.0f, 0.0f, 1.0f); // Màu xanh lá từ 12:31 đến 13:34
} else if ((hour == 13 && min >= 35) || (hour == 14) || (hour == 15 && min == 0)) {
    circleColor = ImVec4(1.0f, 0.0f, 0.0f, 1.0f); // Màu đỏ từ 13:35 đến 15:00
} else if ((hour >= 15 && hour < 18) || (hour == 18 && min <= 30)) {
    circleColor = ImVec4(0.0f, 1.0f, 0.0f, 1.0f); // Màu xanh lá từ 15:01 đến 18:30
} else if (hour == 18 && min >= 31 && min <= 45) {
    circleColor = ImVec4(1.0f, 0.0f, 0.0f, 1.0f); // Màu đỏ từ 18:31 đến 18:45
} else if ((hour == 18 && min >= 46) || hour >= 19 || hour < 8) {
    circleColor = ImVec4(0.0f, 1.0f, 0.0f, 1.0f); // Màu xanh lá từ 18:46 đến 7:59
} else {
    circleColor = ImVec4(1.0f, 0.0f, 0.0f, 1.0f); // Màu đỏ cho các khoảng thời gian còn lại (không cần thiết nhưng giữ lại để đảm bảo)
}
ImVec4 borderColor = ImVec4(43 / 255.0f, 47 / 255.0f, 50 / 255.0f, 1.0f); // Màu viền

// Vẽ hình tròn và viền
// ImDrawList* draw_list = ImGui::GetWindowDrawList();
float radius = 7.5f;
ImVec2 center(cursor_pos.x + 35, cursor_pos.y + 25);

// Vẽ hình tròn
draw_list->AddCircleFilled(center, radius, ImGui::GetColorU32(circleColor));

// Vẽ viền
draw_list->AddCircle(center, radius, ImGui::GetColorU32(borderColor), 0, 3.0f);

// Đảm bảo rằng "=" và hình tròn chồng lên nhau
ImGui::SetCursorPos(ImVec2(15, ImGui::GetWindowSize().y - 40));
ImGui::SetWindowFontScale(0.88f); 
 
     }

    //CỘT BÊN PHẢI
    ImGui::NextColumn();
 ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(40 / 255.0f, 40 / 255.0f, 40 / 255.0f, 1.0f));
    ImFont* font = ImGui::GetIO().Fonts->Fonts[0]; // Get the first font from the font atlas
ImGui::PushFont(font); // Push the font
ImGui::SetWindowFontScale(0.67f); // Set the font scale (18.0f / default font size)
    // Right side content based on selected tab
    if (Settings::Tab == 1)
    {
       
         ImGui::Spacing();
          ImGui::Spacing();
           ImGui::Spacing();
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.5, 6.5)); // Adjust the padding to set the height
     ImGui::SetWindowFontScale(0.95f);
      ImGui::TextColored(ImColor(205 / 255.0f,249 / 255.0f, 0 / 255.0f),"# HACKED FUNCTION ");
 ImGui::SetWindowFontScale(0.67f);
     ImGui::SameLine();
            ImGui::SetWindowFontScale(0.4f);
        ImGui::TextColored(ImColor(160 / 255.0f, 200 / 255.0f, 0 / 255.0f), "YOUR MESAGE TEXT");
        ImGui::SetWindowFontScale(0.67f);

ImVec4 activeColor = ImVec4(50.0f / 255.0f, 50.0f / 255.0f, 50.0f / 255.0f, 1.0f);
ImVec4 defaultColor = ImVec4(205.0f / 255.0f, 250.0f / 255.0f, 0.0f / 255.0f, 1.0f);
ImVec4 borderdefault = ImVec4(120.0f / 255.0f, 120.0f / 255.0f, 120.0f / 255.0f, 1.0f);
ImVec4 borderactive = ImVec4(160.0f / 255.0f, 200.0f / 255.0f, 0.0f / 255.0f, 1.0f);

ImVec4 textdefault = ImVec4(200.0f / 255.0f, 200.0f / 255.0f, 200.0f / 255.0f, 1.0f);
ImVec4 textactive = ImVec4(1.0f / 255.0f, 1.0f / 255.0f, 1.0f / 255.0f, 1.0f);

static bool isDitmeHackerLoActive = true; // Mặc định "DITME HACKER LỎ" on
static bool isHoaThuActive = false; // Mặc định "HOÁ THÚ" off

ImGui::PushStyleColor(ImGuiCol_Button, isDitmeHackerLoActive ? activeColor : defaultColor);
ImGui::PushStyleColor(ImGuiCol_ButtonHovered, defaultColor);
ImGui::PushStyleColor(ImGuiCol_Border, isDitmeHackerLoActive ? borderdefault : borderactive);
ImGui::PushStyleColor(ImGuiCol_Text, isDitmeHackerLoActive ? textdefault : textactive);
ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 10.0f);
ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 3.0f);

if (ImGui::Button("ENABLE MAP", ImVec2(180, 30)))
{
    // Khi button được nhấn, bật cả hai checkbox "Hack Map" và "Ulti"
    map = true;
    skillcd = true;
    isHoaThuActive = true; // Khi nhấn "HOÁ THÚ", đặt isHoaThuActive thành true
    isDitmeHackerLoActive = false; // Khi nhấn "HOÁ THÚ", đặt isDitmeHackerLoActive thành false
  
}
ImGui::PushStyleColor(ImGuiCol_Button, isHoaThuActive ? activeColor : defaultColor);
ImGui::PushStyleColor(ImGuiCol_ButtonHovered, defaultColor);
ImGui::PushStyleColor(ImGuiCol_Border, isHoaThuActive ? borderdefault : borderactive);
ImGui::PushStyleColor(ImGuiCol_Text, isHoaThuActive ? textdefault : textactive);
ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 10.0f);
ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 3.0f);

ImGui::SameLine();
if (ImGui::Button("DISABLE MAP", ImVec2(180, 30)))
{
    // Khi button được nhấn, tắt cả hai checkbox "Hack Map" và "Ulti"
    map = false;
    skillcd = false;
    camera = 1.192f;
   
    isDitmeHackerLoActive = true; // Khi nhấn "DITME HACKER LỎ", đặt isDitmeHackerLoActive thành true
    isHoaThuActive = false; // Khi nhấn "DITME HACKER LỎ", đặt isHoaThuActive thành false
}

ImGui::PopStyleColor(8);
ImGui::PopStyleVar(4);

ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.5, 8.5));

        if (ImGui::BeginTable("Table", 2)) {
          ImGui::TableNextColumn();
          // Table for "SHOW MAP"
          float checkboxWidth = ImGui::GetFrameHeight();
          float spacing = 10.0f;  // Khoảng cách giữa checkbox và text
{
          if (map) {
       ImGui::PushStyleColor(ImGuiCol_CheckMark, ImVec4(155.0f / 255.0f, 192.0f / 255.0f, 0.0f / 255.0f, 1.0f));
          ImGui::PushStyleColor(
              ImGuiCol_FrameBg,
              ImVec4(205.0f / 255.0f, 250.0f / 255.0f, 0.0f / 255.0f, 1.0f));
           ImGui::PushStyleColor(
              ImGuiCol_Text,
              ImVec4(0.0f / 255.0f, 0.0f / 255.0f, 0.0f / 255.0f, 1.0f));
          ImGui::PushStyleColor(ImGuiCol_FrameBgHovered,
                                ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
        } else {
          ImGui::PushStyleColor(
              ImGuiCol_CheckMark,
              ImVec4(160.0f / 255.0f, 200.0f / 255.0f, 0.0f / 255.0f, 1.0f));
          ImGui::PushStyleColor(
              ImGuiCol_FrameBg,
              ImVec4(120.0f / 255.0f, 120.0f / 255.0f, 120.0f / 255.0f, 1.0f));
          ImGui::PushStyleColor(
              ImGuiCol_Text,
              ImVec4(0.0f / 255.0f, 0.0f / 255.0f, 0.0f / 255.0f, 1.0f));
          ImGui::PushStyleColor(ImGuiCol_FrameBgHovered,
                                ImVec4(0.38f, 0.38f, 0.38f, 1.0f));
        }
       
          if(ImGui::Checkbox("map", &map))
          {
          
          }
          ImGui::PopStyleColor(4);

          ImGui::SameLine(checkboxWidth + spacing);
          ImVec2 cursorPos = ImGui::GetCursorPos();
          ImGui::SetCursorPosY(cursorPos.y - 3.0f);
          ImGui::BeginGroup();
           ImGui::PushStyleColor(ImGuiCol_Header, ImVec4(0, 0, 0, 0));
          ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(0, 0, 0, 0));
          ImGui::PushStyleColor(ImGuiCol_HeaderActive, ImVec4(0, 0, 0, 0));
          if (ImGui::Selectable("SHOW MAP", false, ImGuiSelectableFlags_None)) {
            map = !map;
            TriggerHapticFeedback();
          }
          ImGui::SetWindowFontScale(0.4f);
          ImGui::PushStyleColor(
              ImGuiCol_Text,
              ImVec4(160.0f / 255.0f, 160.0f / 255.0f, 160.0f / 255.0f, 1.0f));
          if (ImGui::Selectable("DETECTED ENEMY", false,
                                ImGuiSelectableFlags_None)) {
            map = !map;
            TriggerHapticFeedback();
          }
           ImGui::PopStyleColor();
          ImGui::SetWindowFontScale(0.67f);
          ImGui::EndGroup();
          ImGui::PopStyleColor(3);
}
          ImGui::TableNextColumn();
          // Table for "HIDE NAME"
{
           if (isPlayerName) {
       ImGui::PushStyleColor(ImGuiCol_CheckMark, ImVec4(155.0f / 255.0f, 192.0f / 255.0f, 0.0f / 255.0f, 1.0f));
          ImGui::PushStyleColor(
              ImGuiCol_FrameBg,
              ImVec4(205.0f / 255.0f, 250.0f / 255.0f, 0.0f / 255.0f, 1.0f));
           ImGui::PushStyleColor(
              ImGuiCol_Text,
              ImVec4(0.0f / 255.0f, 0.0f / 255.0f, 0.0f / 255.0f, 1.0f));
          ImGui::PushStyleColor(ImGuiCol_FrameBgHovered,
                                ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
        } else {
          ImGui::PushStyleColor(
              ImGuiCol_CheckMark,
              ImVec4(160.0f / 255.0f, 200.0f / 255.0f, 0.0f / 255.0f, 1.0f));
          ImGui::PushStyleColor(
              ImGuiCol_FrameBg,
              ImVec4(120.0f / 255.0f, 120.0f / 255.0f, 120.0f / 255.0f, 1.0f));
           ImGui::PushStyleColor(
              ImGuiCol_Text,
              ImVec4(0.0f / 255.0f, 0.0f / 255.0f, 0.0f / 255.0f, 1.0f));
          ImGui::PushStyleColor(ImGuiCol_FrameBgHovered,
                                ImVec4(0.38f, 0.38f, 0.38f, 1.0f));
        }

           if(ImGui::Checkbox("HIDE NAME | UID", &isPlayerName))
{
    uid = isPlayerName; // Đồng bộ hóa trạng thái của uid với isPlayerName
    
    // Lưu trạng thái của uid
}

          ImGui::PopStyleColor(4);

          ImGui::SameLine(checkboxWidth + spacing);
           ImVec2 cursorPos2 = ImGui::GetCursorPos();
    ImGui::SetCursorPosY(cursorPos2.y - 3.0f);
          ImGui::BeginGroup();
           ImGui::PushStyleColor(ImGuiCol_Header, ImVec4(0, 0, 0, 0));
          ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(0, 0, 0, 0));
          ImGui::PushStyleColor(ImGuiCol_HeaderActive, ImVec4(0, 0, 0, 0));
   if (ImGui::Selectable("HIDE NAME | UID", false, ImGuiSelectableFlags_None)) {
            isPlayerName = !isPlayerName;
            TriggerHapticFeedback();
            
            
          }
          ImGui::SetWindowFontScale(0.4f);
          ImGui::PushStyleColor(
              ImGuiCol_Text,
              ImVec4(160.0f / 255.0f, 160.0f / 255.0f, 160.0f / 255.0f, 1.0f));
          if (ImGui::Selectable("CHANGE ALL NAME OF PLAYER", false,
                                ImGuiSelectableFlags_None)) {
            isPlayerName = !isPlayerName;
            TriggerHapticFeedback();
            
            
          }
           ImGui::PopStyleColor();
          ImGui::SetWindowFontScale(0.67f);
          ImGui::EndGroup();
          ImGui::PopStyleColor(3);
}
          ImGui::TableNextColumn();
          // Table for "SHOW ULTI"
{
           if (skillcd) {
       ImGui::PushStyleColor(ImGuiCol_CheckMark, ImVec4(155.0f / 255.0f, 192.0f / 255.0f, 0.0f / 255.0f, 1.0f));
          ImGui::PushStyleColor(
              ImGuiCol_FrameBg,
              ImVec4(205.0f / 255.0f, 250.0f / 255.0f, 0.0f / 255.0f, 1.0f));
           ImGui::PushStyleColor(
              ImGuiCol_Text,
              ImVec4(0.0f / 255.0f, 0.0f / 255.0f, 0.0f / 255.0f, 1.0f));
          ImGui::PushStyleColor(ImGuiCol_FrameBgHovered,
                                ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
        } else {
          ImGui::PushStyleColor(
              ImGuiCol_CheckMark,
              ImVec4(160.0f / 255.0f, 200.0f / 255.0f, 0.0f / 255.0f, 1.0f));
          ImGui::PushStyleColor(
              ImGuiCol_FrameBg,
              ImVec4(120.0f / 255.0f, 120.0f / 255.0f, 120.0f / 255.0f, 1.0f));
           ImGui::PushStyleColor(
              ImGuiCol_Text,
              ImVec4(0.0f / 255.0f, 0.0f / 255.0f, 0.0f / 255.0f, 1.0f));
          ImGui::PushStyleColor(ImGuiCol_FrameBgHovered,
                                ImVec4(0.38f, 0.38f, 0.38f, 1.0f));
        }

            if(ImGui::Checkbox("ulti", &skillcd))
            {
              
            }
          ImGui::PopStyleColor(4);

          ImGui::SameLine(checkboxWidth + spacing);
           ImVec2 cursorPos3 = ImGui::GetCursorPos();
    ImGui::SetCursorPosY(cursorPos3.y - 3.0f);
          ImGui::BeginGroup();
           ImGui::PushStyleColor(ImGuiCol_Header, ImVec4(0, 0, 0, 0));
          ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(0, 0, 0, 0));
          ImGui::PushStyleColor(ImGuiCol_HeaderActive, ImVec4(0, 0, 0, 0));
      if (ImGui::Selectable("SHOW ULTI", false, ImGuiSelectableFlags_None)) {
            skillcd = !skillcd;
            TriggerHapticFeedback();
            
          }
          ImGui::SetWindowFontScale(0.4f);
          ImGui::PushStyleColor(
              ImGuiCol_Text,
              ImVec4(160.0f / 255.0f, 160.0f / 255.0f, 160.0f / 255.0f, 1.0f));
          if (ImGui::Selectable("SHOW TIME ULTIMATE CD", false,
                                ImGuiSelectableFlags_None)) {
            skillcd = !skillcd;
            TriggerHapticFeedback();
            
          }
           ImGui::PopStyleColor();
          ImGui::SetWindowFontScale(0.67f);
          ImGui::EndGroup();
          ImGui::PopStyleColor(3);
}
          ImGui::TableNextColumn();
          // Table for "BYPASS SERVER"
          {
           if (lockcam) {
       ImGui::PushStyleColor(ImGuiCol_CheckMark, ImVec4(155.0f / 255.0f, 192.0f / 255.0f, 0.0f / 255.0f, 1.0f));
          ImGui::PushStyleColor(
              ImGuiCol_FrameBg,
              ImVec4(205.0f / 255.0f, 250.0f / 255.0f, 0.0f / 255.0f, 1.0f));
           ImGui::PushStyleColor(
              ImGuiCol_Text,
              ImVec4(0.0f / 255.0f, 0.0f / 255.0f, 0.0f / 255.0f, 1.0f));
          ImGui::PushStyleColor(ImGuiCol_FrameBgHovered,
                                ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
        } else {
          ImGui::PushStyleColor(
              ImGuiCol_CheckMark,
              ImVec4(160.0f / 255.0f, 200.0f / 255.0f, 0.0f / 255.0f, 1.0f));
          ImGui::PushStyleColor(
              ImGuiCol_FrameBg,
              ImVec4(120.0f / 255.0f, 120.0f / 255.0f, 120.0f / 255.0f, 1.0f));
           ImGui::PushStyleColor(
              ImGuiCol_Text,
              ImVec4(0.0f / 255.0f, 0.0f / 255.0f, 0.0f / 255.0f, 1.0f));
          ImGui::PushStyleColor(ImGuiCol_FrameBgHovered,
                                ImVec4(0.38f, 0.38f, 0.38f, 1.0f));
        }

            if(ImGui::Checkbox("LOCKCAM", &lockcam))
            {
             
            }
          ImGui::PopStyleColor(4);

          ImGui::SameLine(checkboxWidth + spacing);
           ImVec2 cursorPos4 = ImGui::GetCursorPos();
    ImGui::SetCursorPosY(cursorPos4.y - 3.0f);
          ImGui::BeginGroup();
           ImGui::PushStyleColor(ImGuiCol_Header, ImVec4(0, 0, 0, 0));
          ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(0, 0, 0, 0));
          ImGui::PushStyleColor(ImGuiCol_HeaderActive, ImVec4(0, 0, 0, 0));
         if (ImGui::Selectable("LOCK CAM", false, ImGuiSelectableFlags_None)) {
            lockcam = !lockcam;
            TriggerHapticFeedback();
           
          }
          ImGui::SetWindowFontScale(0.4f);
          ImGui::PushStyleColor(
              ImGuiCol_Text,
              ImVec4(160.0f / 255.0f, 160.0f / 255.0f, 160.0f / 255.0f, 1.0f));
          if (ImGui::Selectable("PREVENT CAMERA ZOOMING", false,
                                ImGuiSelectableFlags_None)) {
            lockcam = !lockcam;
            TriggerHapticFeedback();
           
          }
           ImGui::PopStyleColor();
          ImGui::SetWindowFontScale(0.67f);
          ImGui::EndGroup();
          ImGui::PopStyleColor(3);
          }
          ImGui::TableNextColumn();
          // Table for "BYPASS SERVER"
{
           if (antiban) {
       ImGui::PushStyleColor(ImGuiCol_CheckMark, ImVec4(155.0f / 255.0f, 192.0f / 255.0f, 0.0f / 255.0f, 1.0f));
          ImGui::PushStyleColor(
              ImGuiCol_FrameBg,
              ImVec4(205.0f / 255.0f, 250.0f / 255.0f, 0.0f / 255.0f, 1.0f));
           ImGui::PushStyleColor(
              ImGuiCol_Text,
              ImVec4(0.0f / 255.0f, 0.0f / 255.0f, 0.0f / 255.0f, 1.0f));
          ImGui::PushStyleColor(ImGuiCol_FrameBgHovered,
                                ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
        } else {
          ImGui::PushStyleColor(
              ImGuiCol_CheckMark,
              ImVec4(160.0f / 255.0f, 200.0f / 255.0f, 0.0f / 255.0f, 1.0f));
          ImGui::PushStyleColor(
              ImGuiCol_FrameBg,
              ImVec4(120.0f / 255.0f, 120.0f / 255.0f, 120.0f / 255.0f, 1.0f));
           ImGui::PushStyleColor(
              ImGuiCol_Text,
              ImVec4(0.0f / 255.0f, 0.0f / 255.0f, 0.0f / 255.0f, 1.0f));
          ImGui::PushStyleColor(ImGuiCol_FrameBgHovered,
                                ImVec4(0.38f, 0.38f, 0.38f, 1.0f));
        }

           if( ImGui::Checkbox("ANTI", &antiban))
           {
            
           }
          ImGui::PopStyleColor(4);

          ImGui::SameLine(checkboxWidth + spacing);
           ImVec2 cursorPos5 = ImGui::GetCursorPos();
    ImGui::SetCursorPosY(cursorPos5.y - 3.0f);
          ImGui::BeginGroup();
           ImGui::PushStyleColor(ImGuiCol_Header, ImVec4(0, 0, 0, 0));
          ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(0, 0, 0, 0));
          ImGui::PushStyleColor(ImGuiCol_HeaderActive, ImVec4(0, 0, 0, 0));
           if (ImGui::Selectable("ANTIBAN | BYPASS", false, ImGuiSelectableFlags_None)) {
            antiban = !antiban;
            TriggerHapticFeedback();
            
          }
          ImGui::SetWindowFontScale(0.4f);
          ImGui::PushStyleColor(
              ImGuiCol_Text,
              ImVec4(160.0f / 255.0f, 160.0f / 255.0f, 160.0f / 255.0f, 1.0f));
          if (ImGui::Selectable("ANTIBAN ", false,
                                ImGuiSelectableFlags_None)) {
            antiban = !antiban;
            TriggerHapticFeedback();
            
          }
           ImGui::PopStyleColor();
          ImGui::SetWindowFontScale(0.67f);

          ImGui::EndGroup();
          ImGui::PopStyleColor(3);
}
          ImGui::TableNextColumn();

{
           if (HideLine) {
       ImGui::PushStyleColor(ImGuiCol_CheckMark, ImVec4(155.0f / 255.0f, 192.0f / 255.0f, 0.0f / 255.0f, 1.0f));
          ImGui::PushStyleColor(
              ImGuiCol_FrameBg,
              ImVec4(205.0f / 255.0f, 250.0f / 255.0f, 0.0f / 255.0f, 1.0f));
           ImGui::PushStyleColor(
              ImGuiCol_Text,
              ImVec4(0.0f / 255.0f, 0.0f / 255.0f, 0.0f / 255.0f, 1.0f));
          ImGui::PushStyleColor(ImGuiCol_FrameBgHovered,
                                ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
        } else {
          ImGui::PushStyleColor(
              ImGuiCol_CheckMark,
              ImVec4(160.0f / 255.0f, 200.0f / 255.0f, 0.0f / 255.0f, 1.0f));
          ImGui::PushStyleColor(
              ImGuiCol_FrameBg,
              ImVec4(120.0f / 255.0f, 120.0f / 255.0f, 120.0f / 255.0f, 1.0f));
           ImGui::PushStyleColor(
              ImGuiCol_Text,
              ImVec4(0.0f / 255.0f, 0.0f / 255.0f, 0.0f / 255.0f, 1.0f));
          ImGui::PushStyleColor(ImGuiCol_FrameBgHovered,
                                ImVec4(0.38f, 0.38f, 0.38f, 1.0f));
        }

            if(ImGui::Checkbox("Hideline", &HideLine))
            {
            
            }
          ImGui::PopStyleColor(4);

          ImGui::SameLine(checkboxWidth + spacing);
           ImVec2 cursorPos5 = ImGui::GetCursorPos();
    ImGui::SetCursorPosY(cursorPos5.y - 3.0f);
          ImGui::BeginGroup();
           ImGui::PushStyleColor(ImGuiCol_Header, ImVec4(0, 0, 0, 0));
          ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(0, 0, 0, 0));
          ImGui::PushStyleColor(ImGuiCol_HeaderActive, ImVec4(0, 0, 0, 0));
           if (ImGui::Selectable("HIDE RED RAY ELSU", false, ImGuiSelectableFlags_None)) {
            HideLine = !HideLine;
          
            TriggerHapticFeedback();
          }
          ImGui::SetWindowFontScale(0.4f);
          ImGui::PushStyleColor(
              ImGuiCol_Text,
              ImVec4(160.0f / 255.0f, 160.0f / 255.0f, 160.0f / 255.0f, 1.0f));
          if (ImGui::Selectable("CANCEL ANIMATION", false,
                                ImGuiSelectableFlags_None)) {
            HideLine = !HideLine;
            TriggerHapticFeedback();
          
          }
           ImGui::PopStyleColor();
          ImGui::SetWindowFontScale(0.67f);

          ImGui::EndGroup();
          ImGui::PopStyleColor(3);
}
          ImGui::EndTable();
        }
        ImGui::Spacing();
        ImGui::Spacing();
        ImGui::Spacing();
        ImGui::SetWindowFontScale(0.85f);
        ImGui::TextColored(ImColor(205 / 255.0f, 249 / 255.0f, 0 / 255.0f),
                           "# DRONE VIEW CAMERA");
        ImGui::SetWindowFontScale(0.67f);
        ImGui::SameLine();
        ImGui::TextColored(
            ImColor(130 / 255.0f, 130 / 255.0f, 130 / 255.0f),
            "__________________________________________________________________"
            "__________________________________________________________________"
            "__________________________________________________________________"
            "________________________________________________________");
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(9, 11));
        ImGui::PushStyleVar(ImGuiStyleVar_GrabMinSize, 30);
        ImGui::PushStyleVar(ImGuiStyleVar_GrabRounding, 8.5);
        ImGui::SetNextItemWidth(350); 
        if(ImGui::SliderFloat("##camvieư", &camera, 0.5f, 6.0f, "Cam Value [ %.2f ]"))
        {
        }
        ImGui::SetNextItemWidth(350); 
    if(ImGui::SliderFloat("##fovview", &drone, 0.5f, 20.0f, "FOV Value [ %.2f ]"))
        {
        }
        ImGui::PopStyleVar(3);


        //         ImGui::SetWindowFontScale(3.1f);
        // ImGui::TextColored(ImColor(150 / 255.0f, 150 / 255.0f, 150 / 255.0f), "+");
        // ImGui::SetWindowFontScale(0.67f);
    }
    else if (Settings::Tab == 2)
    {
        ImGui::Spacing();
         ImGui::Spacing();
          ImGui::Spacing();
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.5, 6.5));
        ImGui::SetWindowFontScale(1.0f);
        ImGui::TextColored(ImColor(205 / 255.0f,249 / 255.0f, 0 / 255.0f),"# AIMBOT SKILL SETTING" );
          ImGui::SetWindowFontScale(0.67f);

      
     ImGui::BeginChild("CheckboxBackground", ImVec2(187, 32), true, ImGuiWindowFlags_NoScrollbar);

// Set background color

ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(150.0f / 255.0f, 150.0f / 255.0f, 150.0f / 255.0f, 1.0f));

ImGui::SetCursorPos(ImVec2(ImGui::GetCursorPos().x + 7, ImGui::GetCursorPos().y + 3));

// First checkbox section
if (AimSkill) {
    ImGui::PushStyleColor(ImGuiCol_CheckMark, ImVec4(0.0f / 255.0f, 0.0f / 255.0f, 0.0f / 255.0f, 1.0f));
     ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(205.0f / 255.0f, 250.0f / 255.0f, 0.0f / 255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
} else {
    ImGui::PushStyleColor(ImGuiCol_CheckMark, ImVec4(160.0f / 255.0f, 200.0f / 255.0f, 0.0f / 255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(120.0f / 255.0f, 120.0f / 255.0f, 120.0f / 255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(160.0f / 255.0f, 160.0f / 255.0f, 160.0f / 255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(0.38f, 0.38f, 0.38f, 1.0f));
}
ImGui::Checkbox("NORMAL", &AimSkill);
ImGui::PopStyleColor(4);
// Second checkbox section
ImGui::SameLine();
if (AutoTrung) {
   ImGui::PushStyleColor(ImGuiCol_CheckMark, ImVec4(0.0f / 255.0f, 0.0f / 255.0f, 0.0f / 255.0f, 1.0f));
     ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(205.0f / 255.0f, 250.0f / 255.0f, 0.0f / 255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
} else {
    ImGui::PushStyleColor(ImGuiCol_CheckMark, ImVec4(160.0f / 255.0f, 200.0f / 255.0f, 0.0f / 255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(120.0f / 255.0f, 120.0f / 255.0f, 120.0f / 255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(160.0f / 255.0f, 160.0f / 255.0f, 160.0f / 255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(0.38f, 0.38f, 0.38f, 1.0f));
}
ImGui::Checkbox("FOLLOW", &AutoTrung);

// Pop style colors
ImGui::PopStyleColor(4);


// End child region
ImGui::EndChild();

ImGui::PopStyleColor();


    ImGui::SameLine();
        //     ImGui::SetWindowFontScale(0.32f);
        // ImGui::TextColored(ImColor(150 / 255.0f, 150 / 255.0f, 150 / 255.0f), "TỰ ĐỘNG CHỌN MỤC TIÊU KHÔNG THỂ ĐỊNH HƯỚNG\n [ KHÔNG KHUYẾN KHÍCH SỬ DỤNG ]");
        // ImGui::SetWindowFontScale(0.67f);
       ImGui::SetCursorPos(ImVec2(ImGui::GetCursorPos().x + 0, ImGui::GetCursorPos().y + 4));
        if (aimSkill1){
      ImGui::PushStyleColor(ImGuiCol_CheckMark, ImVec4(0.0f / 255.0f, 0.0f / 255.0f, 0.0f / 255.0f, 1.0f));
     ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(205.0f / 255.0f, 250.0f / 255.0f, 0.0f / 255.0f, 1.0f));
    // Đổi màu văn bản thành màu trắng
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
     ImGui::PushStyleColor( ImGuiCol_FrameBgHovered, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
}
else
{
    // Inactive: Chuyển màu nền thành màu xám nhạt (220, 220, 220)
     ImGui::PushStyleColor(ImGuiCol_CheckMark, ImVec4(160.0f / 255.0f, 200.0f / 255.0f, 0.0f / 255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(50.0f / 255.0f, 50.0f / 255.0f, 50.0f / 255.0f, 1.0f));
    // Đổi màu văn bản thành màu xám
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(160.0f / 255.0f, 160.0f / 255.0f, 160.0f / 255.0f, 1.0f));
     ImGui::PushStyleColor( ImGuiCol_FrameBgHovered, (0.38f, 0.38f, 0.38f, 1.00f));
}
          ImGui::Checkbox("S1", &aimSkill1);
ImGui::PopStyleColor(4);        
        ImGui::SameLine();
         
        if (aimSkill2){
      ImGui::PushStyleColor(ImGuiCol_CheckMark, ImVec4(0.0f / 255.0f, 0.0f / 255.0f, 0.0f / 255.0f, 1.0f));
     ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(205.0f / 255.0f, 250.0f / 255.0f, 0.0f / 255.0f, 1.0f));
    // Đổi màu văn bản thành màu trắng
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
     ImGui::PushStyleColor( ImGuiCol_FrameBgHovered, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
}
else
{
    // Inactive: Chuyển màu nền thành màu xám nhạt (220, 220, 220)
     ImGui::PushStyleColor(ImGuiCol_CheckMark, ImVec4(160.0f / 255.0f, 200.0f / 255.0f, 0.0f / 255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(50.0f / 255.0f, 50.0f / 255.0f, 50.0f / 255.0f, 1.0f));
    // Đổi màu văn bản thành màu xám
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(160.0f / 255.0f, 160.0f / 255.0f, 160.0f / 255.0f, 1.0f));
     ImGui::PushStyleColor( ImGuiCol_FrameBgHovered, (0.38f, 0.38f, 0.38f, 1.00f));
}
         ImGui::Checkbox("S2", &aimSkill2);
ImGui::PopStyleColor(4);         
        ImGui::SameLine();
           
        if (aimSkill3){
     ImGui::PushStyleColor(ImGuiCol_CheckMark, ImVec4(160.0f / 255.0f, 200.0f / 255.0f, 0.0f / 255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(255.0f / 255.0f, 255.0f / 255.0f, 255.0f / 255.0f, 1.0f));
    // Đổi màu văn bản thành màu trắng
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
     ImGui::PushStyleColor( ImGuiCol_FrameBgHovered, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
}
else
{
    // Inactive: Chuyển màu nền thành màu xám nhạt (220, 220, 220)
     ImGui::PushStyleColor(ImGuiCol_CheckMark, ImVec4(160.0f / 255.0f, 200.0f / 255.0f, 0.0f / 255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(50.0f / 255.0f, 50.0f / 255.0f, 50.0f / 255.0f, 1.0f));
    // Đổi màu văn bản thành màu xám
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(160.0f / 255.0f, 160.0f / 255.0f, 160.0f / 255.0f, 1.0f));
     ImGui::PushStyleColor( ImGuiCol_FrameBgHovered, (0.38f, 0.38f, 0.38f, 1.00f));
}
         ImGui::Checkbox("S3", &aimSkill3);
ImGui::PopStyleColor(4);         
      
        ImGui::Text("RADIUS AIM | 25M FOR USE");
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(9, 11)); // Adjust the padding to set the height
ImGui::PushStyleVar(ImGuiStyleVar_GrabMinSize, 28); // Ensure the grab handle is square with a size of 30x30
ImGui::PushStyleVar(ImGuiStyleVar_GrabRounding, 8.5); // Set the corner radius of the grab handle to 5 pixels
// Create the slider
        ImGui::SliderInt("", &Radius, 0, 50, "%dm");
// Pop the style variables to revert back to the previous settings
ImGui::PopStyleVar(3);
ImGui::SameLine();
  if (ImGui::Button("25M", ImVec2(35, 37)))
{
Radius = 25;
}      
  ImGui::SameLine();
         ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8, 8)); // Adjust the padding to set the height
        if (ImGui::Button("?", ImVec2(35, 37)))
        {
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Hướng Dẫn Chức Năng Aim"
                                                                           message:@"Aim Xoay: Khi Giữ Chiêu Thì Chiêu Sẽ Tự Động Định Hướng (Có Thể Tái Định Hướng)\nAim Dí: Khi Giữ Chiêu Thì Sẽ Dí Vào Địch (Không Tái Định Hướng)\nNếu Muốn Dùng Aim Dí Thì Hãy Bật Cả Aim Dí + Aim Xoay\nTầm Aim Để Mức Nào Cũng Được"
                                                                    preferredStyle:UIAlertControllerStyleAlert];
            UIAlertAction *okAction = [UIAlertAction actionWithTitle:@"OK TÔI ĐÃ ĐỌC KỸ HƯỚNG DẪN SỬ DỤNG" style:UIAlertActionStyleDefault handler:nil];
            [alert addAction:okAction];
            UIViewController *viewController = [UIApplication sharedApplication].keyWindow.rootViewController;
            [viewController presentViewController:alert animated:YES completion:nil];
        }
        ImGui::Spacing();
         ImGui::SetWindowFontScale(0.85f);
        ImGui::TextColored(ImColor(205, 250, 0), "# PLAYS WITH BOT / AI");
         ImGui::SetWindowFontScale(0.67f);
        ImGui::SameLine();
         ImGui::TextColored(ImColor(77, 77, 77), "_____________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________");
             if (ImGui::BeginTable("Table", 3)) {
    // First Checkbox
    ImGui::TableNextColumn();
    if (onehit){
      ImGui::PushStyleColor(ImGuiCol_CheckMark, ImVec4(0.0f / 255.0f, 0.0f / 255.0f, 0.0f / 255.0f, 1.0f));
     ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(205.0f / 255.0f, 250.0f / 255.0f, 0.0f / 255.0f, 1.0f));
    // Đổi màu văn bản thành màu trắng
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
     ImGui::PushStyleColor( ImGuiCol_FrameBgHovered, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
}
else
{
    // Inactive: Chuyển màu nền thành màu xám nhạt (220, 220, 220)
     ImGui::PushStyleColor(ImGuiCol_CheckMark, ImVec4(160.0f / 255.0f, 200.0f / 255.0f, 0.0f / 255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(50.0f / 255.0f, 50.0f / 255.0f, 50.0f / 255.0f, 1.0f));
    // Đổi màu văn bản thành màu xám
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(160.0f / 255.0f, 160.0f / 255.0f, 160.0f / 255.0f, 1.0f));
     ImGui::PushStyleColor( ImGuiCol_FrameBgHovered, (0.38f, 0.38f, 0.38f, 1.00f));
}
    ImGui::Checkbox("ONE HIT", &onehit);
ImGui::PopStyleColor(4);  
    // Second Checkbox
    ImGui::TableNextColumn();
    if (AutoWinInGame){
      ImGui::PushStyleColor(ImGuiCol_CheckMark, ImVec4(0.0f / 255.0f, 0.0f / 255.0f, 0.0f / 255.0f, 1.0f));
     ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(205.0f / 255.0f, 250.0f / 255.0f, 0.0f / 255.0f, 1.0f));
    // Đổi màu văn bản thành màu trắng
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
     ImGui::PushStyleColor( ImGuiCol_FrameBgHovered, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
}
else
{
    // Inactive: Chuyển màu nền thành màu xám nhạt (220, 220, 220)
     ImGui::PushStyleColor(ImGuiCol_CheckMark, ImVec4(160.0f / 255.0f, 200.0f / 255.0f, 0.0f / 255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(50.0f / 255.0f, 50.0f / 255.0f, 50.0f / 255.0f, 1.0f));
    // Đổi màu văn bản thành màu xám
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(160.0f / 255.0f, 160.0f / 255.0f, 160.0f / 255.0f, 1.0f));
     ImGui::PushStyleColor( ImGuiCol_FrameBgHovered, (0.38f, 0.38f, 0.38f, 1.00f));
}
    ImGui::Checkbox("AUTO WIN", &AutoWinInGame);
ImGui::PopStyleColor(4);  
    // Third Checkbox
    ImGui::TableNextColumn();
    if (skill0s){
      ImGui::PushStyleColor(ImGuiCol_CheckMark, ImVec4(0.0f / 255.0f, 0.0f / 255.0f, 0.0f / 255.0f, 1.0f));
     ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(205.0f / 255.0f, 250.0f / 255.0f, 0.0f / 255.0f, 1.0f));
    // Đổi màu văn bản thành màu trắng
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
     ImGui::PushStyleColor( ImGuiCol_FrameBgHovered, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
}
else
{
    // Inactive: Chuyển màu nền thành màu xám nhạt (220, 220, 220)
     ImGui::PushStyleColor(ImGuiCol_CheckMark, ImVec4(160.0f / 255.0f, 200.0f / 255.0f, 0.0f / 255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(50.0f / 255.0f, 50.0f / 255.0f, 50.0f / 255.0f, 1.0f));
    // Đổi màu văn bản thành màu xám
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(160.0f / 255.0f, 160.0f / 255.0f, 160.0f / 255.0f, 1.0f));
     ImGui::PushStyleColor( ImGuiCol_FrameBgHovered, (0.38f, 0.38f, 0.38f, 1.00f));
}
    ImGui::Checkbox("NO CD", &skill0s);
ImGui::PopStyleColor(4);  
    // Fourth Checkbox
    ImGui::TableNextColumn();
    if (fullskin){
      ImGui::PushStyleColor(ImGuiCol_CheckMark, ImVec4(0.0f / 255.0f, 0.0f / 255.0f, 0.0f / 255.0f, 1.0f));
     ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(205.0f / 255.0f, 250.0f / 255.0f, 0.0f / 255.0f, 1.0f));
    // Đổi màu văn bản thành màu trắng
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
     ImGui::PushStyleColor( ImGuiCol_FrameBgHovered, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
}
else
{
    // Inactive: Chuyển màu nền thành màu xám nhạt (220, 220, 220)
     ImGui::PushStyleColor(ImGuiCol_CheckMark, ImVec4(160.0f / 255.0f, 200.0f / 255.0f, 0.0f / 255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(50.0f / 255.0f, 50.0f / 255.0f, 50.0f / 255.0f, 1.0f));
    // Đổi màu văn bản thành màu xám
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(160.0f / 255.0f, 160.0f / 255.0f, 160.0f / 255.0f, 1.0f));
     ImGui::PushStyleColor( ImGuiCol_FrameBgHovered, (0.38f, 0.38f, 0.38f, 1.00f));
}
    ImGui::Checkbox("TESTSKIN", &fullskin);
ImGui::PopStyleColor(4);  
        ImGui::TableNextColumn();
    if (balo){
      ImGui::PushStyleColor(ImGuiCol_CheckMark, ImVec4(0.0f / 255.0f, 0.0f / 255.0f, 0.0f / 255.0f, 1.0f));
     ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(205.0f / 255.0f, 250.0f / 255.0f, 0.0f / 255.0f, 1.0f));
    // Đổi màu văn bản thành màu trắng
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
     ImGui::PushStyleColor( ImGuiCol_FrameBgHovered, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
}
else
{
    // Inactive: Chuyển màu nền thành màu xám nhạt (220, 220, 220)
     ImGui::PushStyleColor(ImGuiCol_CheckMark, ImVec4(160.0f / 255.0f, 200.0f / 255.0f, 0.0f / 255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(50.0f / 255.0f, 50.0f / 255.0f, 50.0f / 255.0f, 1.0f));
    // Đổi màu văn bản thành màu xám
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(160.0f / 255.0f, 160.0f / 255.0f, 160.0f / 255.0f, 1.0f));
     ImGui::PushStyleColor( ImGuiCol_FrameBgHovered, (0.38f, 0.38f, 0.38f, 1.00f));
}
    ImGui::Checkbox("SELL ALL BALO", &balo);
ImGui::PopStyleColor(4);  
     ImGui::TableNextColumn();

    ImGui::EndTable();
}

ImGui::SetCursorPosY(ImGui::GetCursorPosY() - 10); // Move down by 10 pixels

      
    }
    else if (Settings::Tab == 3)
    {
         ImGui::Spacing();
          ImGui::Spacing();
           ImGui::Spacing();
         ImGui::SetWindowFontScale(0.85f);
        ImGui::TextColored(ImColor(205 / 255.0f,249 / 255.0f, 0 / 255.0f),"TOOLS FOR USER CUSTOM YOUR GAME !!!");    
        ImGui::Spacing();
        
         
ImVec4 borderColor = ImVec4(0.58f, 0.58f, 0.58f, 0.0f); // RGB: 150, 150, 150
ImGui::PushStyleColor(ImGuiCol_Border, borderColor);
ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 9.0f); // Rounded corners
ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8.0f, 8.0f)); // Padding inside the child window
ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(5.0f, 5.0f)); // Padding for frame elements

ImVec2 childSize = ImVec2(350+15+15, 90);
ImGui::BeginChild("ChildBorder", childSize, true, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

ImGui::SetWindowFontScale(0.67f);
ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1 / 255.0f, 113 / 255.0f, 227 / 255.0f, 1.0f));
ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1 / 255.0f, 113 / 255.0f, 227 / 255.0f, 1.0f));
ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(255 / 255.0f, 255 / 255.0f, 255 / 255.0f, 1.0f));
if (ImGui::Button("( MODSKIN VIA LINK", ImVec2(163+15, 40)))
{

}
ImGui::PopStyleColor(3);  // Có 4 PushStyleColor được gọi


ImGui::SameLine();
ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1 / 255.0f, 113 / 255.0f, 227 / 255.0f, 1.0f));
ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1 / 255.0f, 113 / 255.0f, 227 / 255.0f, 1.0f));
ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(255 / 255.0f, 255 / 255.0f, 255 / 255.0f, 1.0f));
if (ImGui::Button(") MOD SKIN VIA FILE", ImVec2(163+15, 40)))
{
 
}
ImGui::PopStyleColor(3);  // Có 4 PushStyleColor được gọi

ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(255 / 255.0f, 255 / 255.0f, 255 / 255.0f, 1.0f));
ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(255 / 255.0f, 255 / 255.0f, 255 / 255.0f, 1.0f));
ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(255 / 255.0f, 86 / 255.0f, 102 / 255.0f, 1.0f));
if (ImGui::Button("DELETE MOD SKIN", ImVec2(163+15, 31)))
{
 
}
ImGui::PopStyleColor(3);  // Có 4 PushStyleColor được gọi


ImGui::SameLine();
ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(255 / 255.0f, 86 / 255.0f, 102 / 255.0f, 1.0f));
ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(255 / 255.0f, 86 / 255.0f, 102 / 255.0f, 1.0f));
ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(255 / 255.0f, 255 / 255.0f, 255 / 255.0f, 1.0f));
if (ImGui::Button("FORCE UPDATE", ImVec2(163+15, 31)))
{
}
ImGui::PopStyleColor(3);  // Có 4 PushStyleColor được gọi


ImGui::EndChild();
ImGui::PopStyleVar(3); // Pop ChildRounding, WindowPadding, and FramePadding
ImGui::PopStyleColor(); // Pop border color

ImGui::SetWindowFontScale(0.75f);
          ImGui::TextColored(ImColor(255, 255, 255),  "CUSTOM TEXT");
          ImGui::SetWindowFontScale(0.67f);
          ImGui::SameLine();  
 ImGui::TextColored(ImColor(77, 77, 77),  " __________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________");
           if (ImGui::Button("UID TEXT", ImVec2(400, 30)))
        {
        }      
        
 ImGui::Spacing();ImGui::SetWindowFontScale(0.75f);
        ImGui::TextColored(ImColor(212, 32, 78),  "BONUS ZONE");
        ImGui::SetWindowFontScale(0.67f);
        ImGui::SameLine();
        ImGui::TextColored(ImColor(77, 77, 77),  " __________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________");
    
        if (ImGui::Button("EXIT APP RISK", ImVec2(190, 30)))
        {
            exit(0);
                
        }
         ImGui::SameLine();
 ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(235 / 255.0f, 220 / 255.0f, 220 / 255.0f, 1.0f));
ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(235 / 255.0f, 220 / 255.0f, 220 / 255.0f, 1.0f));

// Thiết lập màu chữ mới là màu trắng
ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(220 / 255.0f, 50 / 255.0f, 50 / 255.0f, 1.0f));


// Tạo nút và kiểm tra sự kiện bấm
if (ImGui::Button("LOGOUT ACC", ImVec2(190, 30)))
    {
    }

// Pop các style đã đẩy vào
ImGui::PopStyleColor(3);  // Có 4 PushStyleColor được gọi
      
    }
    else if (Settings::Tab == 4)
    {
           ImGui::Spacing();
          ImGui::Spacing();
           ImGui::Spacing();
        ImGui::SetWindowFontScale(0.95f);
        ImGui::TextColored(ImColor(205, 250, 0), "All API Written By NguyenThien");
        ImGui::SetWindowFontScale(0.75f);
        ImGui::Text(" BẢNG GIÁ CHỨNG CHỈ CÁ activeButtonNHÂN ");
        ImGui::SetWindowFontScale(0.60f);
        ImGui::Text(" 169,000 VND | LẤY NGAY | BẢO HÀNH 12 THÁNG");
        ImGui::Text(" 60,000 VND | ĐỢI 72G | BẢO HÀNH 6 THÁNG");
            ImGui::Spacing();
          ImGui::Spacing();
         ImGui::SetWindowFontScale(1.0f);
        ImGui::TextColored(ImColor(255, 150, 53),"TESTFLIGHT GAME");
       
      
  ImGui::SetCursorPos(ImVec2(ImGui::GetCursorPos().x + 0, ImGui::GetCursorPos().y - 10));
  ImGui::BeginGroup();
  ImGui::Spacing();
   ImGui::Spacing();
   ImGui::Spacing();
           ImGui::Text("Liên Quân WtHaxVN");
ImGui::SetWindowFontScale(0.67f);
ImVec2 cursorPos = ImGui::GetCursorPos();
cursorPos.y -= 5.0f; // Adjust this value to control the spacing
ImGui::SetCursorPos(cursorPos);
 ImGui::Text("DOWNLOAD ON");
  ImGui::SameLine();

  ImGui::TextColored(ImColor(1, 113, 227),"TESTFLIGHT");

  ImGui::SetWindowFontScale(0.67f);

ImVec2 cursorPosafter = ImGui::GetCursorPos();
cursorPosafter.y += 5.0f; // Adjust this value to control the spacing
ImGui::SetCursorPos(cursorPosafter);
  ImGui::SetWindowFontScale(0.8f);
 ImGui::EndGroup();
   ImGui::SameLine();
ImVec4 xanhnhat = ImVec4(25.0f / 255.0f, 184.0f / 255.0f, 240.0f / 255.0f, 1.0f); // Màu xanh nhạt
ImVec4 xanhdam = ImVec4(23.0f / 255.0f, 99.0f / 255.0f, 225.0f / 255.0f, 1.0f); // Màu xanh đậm
ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1.0f, 1.0f, 1.0f, 0.0f)); // Đặt màu nút về màu trắng
ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f, 1.0f, 1.0f, 0.0f)); // Màu khi di chuột qua nút
ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1.0f, 1.0f, 1.0f, 0.0f)); // Màu khi nhấn nút

ImVec2 buttonSize = ImVec2(200, 45); // Kích thước nút
ImVec2 buttonPos = ImGui::GetCursorScreenPos(); // Vị trí nút trên màn hình

// Vẽ nền gradient cho nút với độ bo góc là 9
ImU32 redU32 = ImColor(xanhnhat);
ImU32 blueU32 = ImColor(xanhdam);
ImDrawList* draw_list = ImGui::GetWindowDrawList();
draw_list->AddRectFilledMultiColor(buttonPos, ImVec2(buttonPos.x + buttonSize.x, buttonPos.y + buttonSize.y), redU32, blueU32, blueU32, redU32);
draw_list->AddRect(buttonPos, ImVec2(buttonPos.x + buttonSize.x, buttonPos.y + buttonSize.y), ImColor(26, 26, 26, 255), 12.0f, ImDrawFlags_RoundCornersAll, 11.0f);

// Vẽ nút bình thường lên trên nền gradient
if (ImGui::Button("BẢN MENU GIÁ HẠT DẺ", buttonSize))
{
[[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://wthaxvn.site/id/testflight"]];}

ImGui::PopStyleColor(3); // Khôi phục màu gốc của nút


ImGui::SetWindowFontScale(1.15f);
 ImGui::Spacing();
  ImGui::Spacing();
  ImGui::TextColored(ImColor(220, 220, 220),"   BẠN CÓ THỂ LIÊN HỆ VỚI TÔI QUA");
        
   ImGui::SetWindowFontScale(0.67f);
ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(205 / 255.0f, 250 / 255.0f, 0 / 255.0f, 1.0f));
ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(205 / 255.0f, 250 / 255.0f, 0 / 255.0f, 1.0f));
ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0 / 255.0f, 0 / 255.0f, 0 / 255.0f, 1.0f));
ImGui::SetWindowFontScale(1.0f);

// Set frame rounding to 20px
ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 30.0f);

if (ImGui::Button("ĐẾN TRANG THÔNG TIN TÁC GIẢ", ImVec2(380, 40)))
{
    Settings::Tab = 6;
}

// Restore previous frame rounding value
ImGui::PopStyleVar();
ImGui::PopStyleColor(3);

ImGui::SetWindowFontScale(0.75f);
ImGui::TextColored(ImColor(205, 250, 0), "Powered By");
ImGui::SameLine();
ImGuiTextURL(" WtHaxVN [ Nguyen Thien ]", "https://wthaxvn.site");

        ImGui::TextColored(ImColor(212, 255, 255), "\n");
    }
    else if (Settings::Tab == 5)
    {
    }
 else if (Settings::Tab == 7)
    {
         ImGui::Spacing();
          ImGui::Spacing();
           ImGui::Spacing();
        ImGui::SetWindowFontScale(0.85f);
ImGui::TextColored(ImColor(205, 250, 0), "# THÔNG TIN KEY");
ImGui::SetWindowFontScale(0.67f);
// PPAPIKey *API = [[PPAPIKey alloc] init];
ImColor yellow(255, 255, 0);
ImColor red(255, 0, 0);

// if (ImGui::BeginTable("Table", 2))
// {
//     // First row

//     ImGui::TableNextColumn();
//     ImGui::TextColored(red, "KEY: ");
//     ImGui::SameLine();
//     ImGui::TextColored(ImColor(1, 113, 227), "%s", [[API getKey] UTF8String]);
//         ImGui::TextColored(red, "CÒN: ");
//     ImGui::SameLine();
//     ImGui::TextColored(ImColor(1, 113, 227), "%s", [[API getKeyExpire] UTF8String]);

//     ImGui::TableNextColumn();
//     if (ImGui::Button("EXIT", ImVec2(55, 37)))
//     {
//         [API exitKey];
//     }
//     ImGui::SameLine();
//     if (ImGui::Button("COPY", ImVec2(55, 35)))
//     {
//         [API copyKey];
//     }

//     ImGui::EndTable();
// }
ImGui::Spacing();
ImGui::SetWindowFontScale(0.85f);
ImGui::TextColored(ImColor(205, 250, 0), "# THÔNG TIN THIẾT BỊ");
ImGui::SetWindowFontScale(0.67f);
    char appName[256] = {0};
    char bundleID[256] = {0};
    char appVersion[256] = {0};
    char deviceModel[256] = {0};
    


 ImGui::Text("THIẾT BỊ: %s", deviceModel);
               ImColor white(255, 255, 255);
                ImGui::TextColored(white, "PIN:");

                ImColor blue(1, 113, 227);
                ImGui::SameLine();
                ImGui::TextColored(blue, " %.0f%%", batteryLevel);

                ImColor green(0, 146, 69);
                ImColor statusTextColor;
                if (device.batteryState == UIDeviceBatteryStateCharging) {
                    statusTextColor = green;
                } else {
                    statusTextColor = red;
                }
                ImGui::SameLine();
                ImGui::TextColored(statusTextColor, "%s", [chargingStatus UTF8String]);

                ImVec4 used_text_color(1/255.0f, 113/255.0f, 227/255.0f, 1);
                ImVec4 used_info_color(1/255.0f, 113/255.0f, 227/255.0f, 1);
                ImGui::SameLine();
                ImGui::TextColored(white, "|  RAM:");
                ImGui::SameLine();
                int used_ram_len = snprintf(used_ram_str, sizeof(used_ram_str), "%s: %d MB", "", used_ram);

                if (used_ram_len > 0) {
                    ImGui::TextColored(used_text_color, "%s", "");
                    ImGui::SameLine();
                    ImGui::TextColored(used_info_color, "%d MB", used_ram);
                }
                ImGui::SameLine(); ImGui::TextColored(white, "/");
                ImGui::SameLine();

                sprintf(free_ram_str, "%d MB", free_ram);
                if (strlen(free_ram_str) > 0) {
                    ImGui::TextColored(ImVec4(1/255.0f, 113/255.0f, 227/255.0f, 1), "");
                    ImGui::SameLine();
                    ImGui::TextColored(ImVec4(1/255.0f, 113/255.0f, 227/255.0f, 1), "%s", free_ram_str);
                }
                ImGui::Spacing();
                ImGui::SetWindowFontScale(0.85f);
ImGui::TextColored(ImColor(205, 250, 0), "# THÔNG TIN ỨNG DỤNG");
    ImGui::SetWindowFontScale(0.67f);

    
    ImGui::Text("App Name: %s", appName);
    ImGui::Text("Bundle ID: %s  |", bundleID);
    ImGui::SameLine();
    ImGui::Text("Phiên bản: %s", appVersion);

    }
    else if (Settings::Tab == 6)
    {   
        ImGui::Spacing();
         ImGui::Spacing();
          ImGui::Spacing();
            ImGui::Spacing();
          ImGui::Spacing();

ImGui::BeginGroup();
ImGui::SetCursorPos(ImVec2(ImGui::GetCursorPos().x + 0, ImGui::GetCursorPos().y - 10));
ImGui::SetWindowFontScale(0.86); 
ImGui::Text("Nguyễn Quốc Thiện");
ImGui::SetWindowFontScale(0.67); 
ImGui::TextColored(ImVec4(200.0f / 255.0f, 200.0f / 255.0f, 200.0f / 255.0f, 1.0f), "Designer Not A Coder / Developer");
ImGui::Spacing();

ImGui::SetWindowFontScale(0.8); 
ImGui::Text("This ImGui Made With");
ImGui::SetWindowFontScale(0.67); 
ImGui::TextColored(ImVec4(200.0f / 255.0f, 200.0f / 255.0f, 200.0f / 255.0f, 1.0f), "VsCode | Adobe Photoshop | Esign");
ImGui::Spacing();

ImGui::SetWindowFontScale(0.8); 
ImGui::Text("Many Thanks To");
ImGui::SetWindowFontScale(0.67); 
ImGui::TextColored(ImVec4(200.0f / 255.0f, 200.0f / 255.0f, 200.0f / 255.0f, 1.0f), "No One");
ImGui::Spacing();


ImGui::EndGroup();

ImGui::Text("Nếu Bạn Yêu Thích Menu Này Và Muốn Mua Source Hoặc Thuê \n Make Menu Hãy Liên Hệ Cho Tôi Qua Zalo / Facebook");
ImGui::Spacing();
ImGui::SetWindowFontScale(1.0); 
ImGui::TextColored(ImVec4(205.0f / 255.0f, 255.0f / 255.0f, 0.0f / 255.0f, 1.0f), "# CONTACT ME VIA");
ImGui::SameLine();
ImGui::TextColored(ImVec4(150.0f / 255.0f, 150.0f / 255.0f, 150.0f / 255.0f, 1.0f), "_____________________________________________________________________________");
//nút liên hệ

RenderZaloGroupButton("https://zalo.me/g/mjzxzy450");
ImGui::SameLine();
ImGui::BeginGroup();
RenderFBButton("https://www.facebook.com/wthi3n.nguye/");
ImGui::SameLine();
RenderMOMOButton("https://me.momo.vn/x3IbTQsgFOi8UOuVT6UqCW");
RenderBIOButton("https://bento.me/wthaxvn");
ImGui::EndGroup();
    }
     ImGui::PopStyleColor(); // Pop the WindowBg color
     ImGui::PopFont();
ImGui::SetWindowFontScale(1.0f); // Reset the font scale
                ImGui::End();
            }


    ImDrawList* draw_list = ImGui::GetBackgroundDrawList();
    ImGuiStyle& style = ImGui::GetStyle();

    ImVec4* colors = style.Colors;

	// style.WindowRounding = 12.000f;
	// style.WindowTitleAlign = ImVec2(0.5, 0.5);
	style.ChildRounding = 9.000f;
	// style.PopupRounding = 6.000f;
	// style.FrameRounding = 20.000f;
	// style.FrameBorderSize = 1.000f;
	// style.GrabRounding = 12.000f;
	// style.TabRounding = 7.000f;
	// style.ButtonTextAlign = ImVec2(0.510f, 0.490f);
    // style.Alpha = 0.9f;
                         
	style.WindowPadding = ImVec2(0, 0);
	style.WindowRounding = 25.0f;
	style.FramePadding = ImVec2(0, 0);
	style.FrameRounding = 9.0f; // Make all elements (checkboxes, etc) circles
	//style.ItemSpacing = ImVec2(12, 8);
	//style.ItemInnerSpacing = ImVec2(8, 6);
	//style.IndentSpacing = 25.0f;
	style.ScrollbarSize = 23.0f;
	style.ScrollbarRounding = 9.0f;
	style.GrabMinSize = 20.0f; // Thực hiện lấy một vòng tròn
	style.GrabRounding = 12.0f;
	style.PopupRounding = 7.f;
	style.Alpha = 1.0;
   //  if (allhack) {
//       if (allhack_active == NO) {
//         ActiveCodePatch("Frameworks/UnityFramework.framework/UnityFramework",0x5EEC550, "1F2003D5", allhack);
//       }
//       allhack_active = YES;
//     } else {
//       if (allhack_active == YES) {
//         ActiveCodePatch("Frameworks/UnityFramework.framework/UnityFramework",  0x5EEC550, "1F2003D5", allhack);
//       }
//       allhack_active = NO;
//     }
    
    if(map){
        if(map_active == NO){
        
        // ActiveCodePatch("Frameworks/UnityFramework.framework/UnityFramework", 0x5331A08, "360080D2");
        // Hello("Frameworks/UnityFramework.framework/UnityFramework", 0x5331A08, "360080D2");

        // ActiveCodePatch("Frameworks/UnityFramework.framework/UnityFramework", 0x5EEC550, "1F2003D5");
        // Hello("Frameworks/UnityFramework.framework/UnityFramework", 0x5EEC550, "1F2003D5");
        // ActiveCodePatch("Frameworks/UnityFramework.framework/UnityFramework", 0x5BF5B7C, "C0035FD6");
        //  Hello("Frameworks/UnityFramework.framework/UnityFramework", 0x5BF5B7C, "C0035FD6");

        //  ActiveCodePatch("Frameworks/UnityFramework.framework/UnityFramework", 0x5455D78, "C0035FD6");
        //  Hello("Frameworks/UnityFramework.framework/UnityFramework", 0x5455D78, "C0035FD6");

        }
        map_active = YES;
    }
    else{ 
        if(map_active == YES){

    //   DeactiveCodePatch("Frameworks/UnityFramework.framework/UnityFramework", 0x5331A08, "360080D2");
    //   DeactiveCodePatch("Frameworks/UnityFramework.framework/UnityFramework", 0x5EEC550, "1F2003D5");
    //    DeactiveCodePatch("Frameworks/UnityFramework.framework/UnityFramework", 0x5BF5B7C, "C0035FD6");
            }
        map_active = NO;
    } 
    

        if(skillcd){
        if(skill_active == NO){
        
    //    ActiveCodePatch("Frameworks/UnityFramework.framework/UnityFramework", 0x5E17B98, "1F2003D5"); 
    //    ActiveCodePatch("Frameworks/UnityFramework.framework/UnityFramework", 0x5E17C28, "33008052");
    //    Hello("Frameworks/UnityFramework.framework/UnityFramework", 0x5E17B98, "1F2003D5");
    //    Hello("Frameworks/UnityFramework.framework/UnityFramework", 0x5E17C28, "33008052");
    //    ActiveCodePatch("Frameworks/UnityFramework.framework/UnityFramework", 0x5E21A50, "370080D2");
    //    Hello("Frameworks/UnityFramework.framework/UnityFramework", 0x5E21A50, "370080D2");
        }
        skill_active = YES;
    }
    else{ 
        if(skill_active == YES){
//       DeactiveCodePatch("Frameworks/UnityFramework.framework/UnityFramework", 0x5E17B98, "1F2003D5"); 
//        DeactiveCodePatch("Frameworks/UnityFramework.framework/UnityFramework", 0x5E17C28, "33008052");
//  DeactiveCodePatch("Frameworks/UnityFramework.framework/UnityFramework", 0x5E21A50, "370080D2");
            }
        skill_active = NO;
    } 
    

    static dispatch_once_t onceToken;
        dispatch_once(&onceToken,^{
                
               
            
        });

           
             
     

    if(antiban){
        if(antiban_active == NO){
            static dispatch_once_t onceToken;
            dispatch_once(&onceToken, ^{
               
               });
            }
        antiban_active = YES;
        }else{
                
        antiban_active = NO;
        }


    if(skill0s){
        if(skill0s_active == NO){
            // ActiveCodePatch("Frameworks/UnityFramework.framework/UnityFramework",  0x53B4FF4 , "00008052C0035FD6"); //public void StartSkillCD(int overrideCDValue = 0, int ratio = 0) { }
            // Hello("Frameworks/UnityFramework.framework/UnityFramework",  0x53B4FF4 , "00008052C0035FD6");
            }
        skill0s_active = YES;
    }
    else{ 
        if(skill0s_active == YES){
            // DeactiveCodePatch("Frameworks/UnityFramework.framework/UnityFramework",  0x53B4FF4 , "00008052C0035FD6");
            }
        skill0s_active = NO;
    }   


    if(onehit){
        if(onehit_active == NO){
            // ActiveCodePatch("Frameworks/UnityFramework.framework/UnityFramework", 0x5281204 , "00E0AFD2C0035FD6"); // private int SetDamage2ZeroOperatorIfNeed(ref HurtDataInfo hurt, int hp) { }
            // Hello("Frameworks/UnityFramework.framework/UnityFramework", 0x5281204 , "00E0AFD2C0035FD6");
            }
        onehit_active = YES;
    }
    else{
        if(onehit_active == YES){
            // DeactiveCodePatch("Frameworks/UnityFramework.framework/UnityFramework", 0x5281204 , "00E0AFD2C0035FD6");
            }
        onehit_active = NO;
    }


    if(fullskin){
        if(fullskin_active == NO){
            // ActiveCodePatch("Frameworks/UnityFramework.framework/UnityFramework", 0x5B6F9BC , "C0035FD6"); // private int SetDamage2ZeroOperatorIfNeed(ref HurtDataInfo hurt, int hp) { }
            // Hello("Frameworks/UnityFramework.framework/UnityFramework", 0x5B6F9BC , "C0035FD6");
            }
        fullskin_active = YES;
    }
    else{
        if(fullskin_active == YES){
            // DeactiveCodePatch("Frameworks/UnityFramework.framework/UnityFramework", 0x5B6F9BC , "C0035FD6");
            }
        fullskin_active = NO;
    }


    if(balo){
        if(balo_active == NO){
            // ActiveCodePatch("Frameworks/UnityFramework.framework/UnityFramework", 0x5BC76EC , "C0035FD6"); // private int SetDamage2ZeroOperatorIfNeed(ref HurtDataInfo hurt, int hp) { }
            // Hello("Frameworks/UnityFramework.framework/UnityFramework", 0x5BC76EC , "C0035FD6");
            }
        balo_active = YES;
    }
    else{
        if(balo_active == YES){
            // DeactiveCodePatch("Frameworks/UnityFramework.framework/UnityFramework", 0x5BC76EC , "C0035FD6");
            }
        balo_active = NO;
    }


    if(uid){
        if(uid_active == NO){
            // ActiveCodePatch("Frameworks/UnityFramework.framework/UnityFramework", 0x5BF5B7C , "C0035FD6"); // private int SetDamage2ZeroOperatorIfNeed(ref HurtDataInfo hurt, int hp) { }
            // Hello("Frameworks/UnityFramework.framework/UnityFramework", 0x5BF5B7C , "C0035FD6");
            }
        uid_active = YES;
    }
    else{
        if(uid_active == YES){
            // DeactiveCodePatch("Frameworks/UnityFramework.framework/UnityFramework", 0x5BF5B7C , "C0035FD6");
            }
        uid_active = NO;
    }





    
            ImGui::Render();
            ImDrawData* draw_data = ImGui::GetDrawData();
            ImGui_ImplMetal_RenderDrawData(draw_data, commandBuffer, renderEncoder);
          
            [renderEncoder popDebugGroup];
            [renderEncoder endEncoding];

            [commandBuffer presentDrawable:view.currentDrawable];
        }

        [commandBuffer commit];
}

- (void)mtkView:(MTKView*)view drawableSizeWillChange:(CGSize)size 
{

}


@end

// Theme by: Thiện 131 
// Share by: @dothanh1110 (đc cấp phép)
// mấy con chó share ko gắn nguồn chết đi || và mấy con chó leak trc đó cx thế nhé
// Zalo: https://zalo.me/g/pmselp698ß