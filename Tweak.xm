/* Snoolie K, (c) 2024 */

#import <UIKit/UIKit.h>
#import <Security/Security.h>

/* Input the path to output the QMC file here, including file extension */
#define OUTPUT_QMC_PATH "/path/to/dump.qmc"

/* Path to an unsigned shortcut file here */
#define UNSIGNED_SHORTCUT_PATH "/path/to/unsigned.shortcut"

@interface WFShortcutSigningContext : NSObject
-(NSData *)generateAuthData;
@end

/* From libqmc.m */

/* qmc types */
typedef enum QmcType_t {
    QMC_RAW,
    QMC_OPTIMIZED,
    QMC_RAW_FLIP,
    QMC_OPTIMIZED_FLIP,
    QMC_WARP,
} QmcType;

uint8_t *raw_qmd_for_private_key_and_auth_data(NSData *privateKey, NSData *authData) {
    unsigned long privKeyLen = [privateKey length];
    unsigned long authDataLen = [authData length];
    size_t qmdSize = privKeyLen + authDataLen + 8;
    uint8_t *qmd = (uint8_t *)malloc(qmdSize * 8);
    char privKeyChar[4];
    privKeyChar[0] = (privKeyLen & 0xFF);
    privKeyChar[1] = ((privKeyLen >> 8) & 0xFF);
    privKeyChar[2] = ((privKeyLen >> 16) & 0xFF);
    privKeyChar[3] = (privKeyLen >> 24);
    memcpy((char *)qmd, "QMD\0", 4);
    memcpy((char *)qmd + 4, privKeyChar, 4);
    memcpy((char *)qmd + 8, [privateKey bytes], privKeyLen);
    memcpy((char *)qmd + 8 + privKeyLen, [authData bytes], authDataLen);
    return qmd;
}
void create_qmc_at_path_for_raw_qmd(NSString *path, uint8_t *qmd, size_t qmd_size) {
    [[NSFileManager defaultManager]createDirectoryAtPath:path withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *qmcInfoPath = [path stringByAppendingPathComponent:@"Info.plist"];
    NSDictionary *qmcInfo = @{
        @"name" : @"data.qmd",
        @"type" : [NSNumber numberWithInt:QMC_RAW],
    };
    [qmcInfo writeToFile:qmcInfoPath atomically:YES];
    NSString *qmcDataPath = [path stringByAppendingPathComponent:@"data.qmd"];
    NSData *qmdData = [NSData dataWithBytesNoCopy:qmd length:qmd_size];
    [qmdData writeToFile:qmcDataPath atomically:YES];
}

%hook WFShortcutPackageFile
-(id)generateSignedShortcutFileRepresentationWithPrivateKey:(SecKeyRef)daKey signingContext:(WFShortcutSigningContext *)signingContext error:(NSError**)err {
 NSData *key = (__bridge NSData *)SecKeyCopyExternalRepresentation(daKey, 0);
 NSData *authData = [signingContext generateAuthData];
 unsigned long privKeyLen = [key length];
 unsigned long authDataLen = [authData length];
 size_t qmdSize = privKeyLen + authDataLen + 8;
 uint8_t *qmd = raw_qmd_for_private_key_and_auth_data(key, authData);
 if (qmd) {
  create_qmc_at_path_for_raw_qmd(@OUTPUT_QMC_PATH, qmd, qmdSize);
 }
 return nil; /* fail on purpose */
}
%end