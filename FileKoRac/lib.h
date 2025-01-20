//
// ModSkinDSGaming.h
// ModSkinDSGM
//
// Created by DS Gaming on 08/02/2021
// Long live Vietnam
//
// djt me bon an cap khong ghi nguon
//

#ifndef ModSkinDSGaming_h
#define ModSkinDSGaming_h
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#define timer(sec) dispatch_after(dispatch_time(DISPATCH_TIME_NOW, sec * NSEC_PER_SEC), dispatch_get_main_queue(), ^

@interface ModSkinDSGM : NSObject

+ (void)ActiveModDSGM; // mod skin ở đây

+ (void)RemoveModDSGM; // xoá mod ở đây

+ (void)ActiveModBackgroud;

/*

    import file .mm vào Makefile: $(TWEAK_NAME)_FILES = ModSkinDSGaming.mm

    import file Header vào main của bạn

    ví dụ code:

    bool isActivate, isRemove = false;

    if (isActivate) {
        [ModSkinDSGM ActiveModDSGM]; // kích hoạt mod
    }

    if (isRemove) {
        [ModSkinDSGM RemoveModDSGM]; // xoá mod
    }
*/

@end

#endif
