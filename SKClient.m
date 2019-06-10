//
//  SKClient.m
//  SKClient
//
//  Created by 박지웅 on 13. 2. 12..
//  Copyright (c) 2013년 Seeroo Information Inc. All rights reserved.
//

#import "SKClient.h"
#import "CkoRsa.h"
#import "SKC_AES.h"

#import "SKC_SBJsonWriter.h"
#import "SKC_SBJsonParser.h"

#import <CommonCrypto/CommonDigest.h>
#include <sys/socket.h> // Per msqr
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#import <sys/utsname.h>

#include "NSData+Ascii85.h"

static NSString* TAG = @"SKClient";
static NSString* COPYRIGHT = @"2013 seeroo inc.";
static NSString* UNLOCK_KEY = @"SEEROORSA_bsGh8n0F0AsT";
static NSString* DEFAULT_KEYID = @"1";
static NSString* DEFAULT_PUBKEY_MOD = @"AKb55vHrgYTLCzcTBmsg6d6q0jLdhM/xkaQ1fD6x/xq/98YYnchMN70Hohafl5UbI5C1HQ8OpLKdbQ9a8WP03d0mySH8HNJH11BjKNgFpoDSEWy05e64UgyH7uVs7Er4Bnnd27YOfent1crRTqeJXsULQ0tFETRQrzTXtJUoBdOx";
static NSString* DEFAULT_PUBKEY_EXP = @"AQAB";
static NSString* DEFAULT_SUPERKEY = @"12345678901234567890123456789012"; // 32byte = 256bit, AES 기본 암호화 키
static NSString* DEFAULT_STORE_SUPERKEY = @"seerooinc.seerooinc.seerooinc.13"; // 32byte = 256bit, 단말에 keyID, keyExp, keyMod 저장 시 사용
//static NSString* NATIVE_LIBRARY_NAME = @"skclient";

static NSString* SK_POSSESION_TRANDATE = @"SPT";

static NSString* SK_KEY_ID = @"SKCI";
static NSString* SK_KEY_EXP = @"SKCE";
static NSString* SK_KEY_MOD = @"SKCM";

static NSString* SK_KEY_ID_TS = @"SKCI_TS";
static NSString* SK_KEY_EXP_TS = @"SKCE_TS";
static NSString* SK_KEY_MOD_TS = @"SKCM_TS";

static NSString* _version = @"1.5.0";

static const char _base64EncodingTable[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const short _base64DecodingTable[256] = {
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -1, -1, -2, -1, -1, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    -1, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, 62, -2, -2, -2, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -2, -2, -2, -2, -2, -2,
    -2,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -2, -2, -2, -2, -2,
    -2, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2
};

#define P(fmt, ...) do { NSLog((@"|SKClient|P> %s(%d) " fmt), __FUNCTION__, __LINE__, ##__VA_ARGS__); } while(0);
#define L(fmt, ...) do { if(isDebugEnabled) {NSLog((@"|SKClient|D> %s(%d) " fmt), __FUNCTION__, __LINE__, ##__VA_ARGS__); }} while(0);
#define P(fmt, ...) do { if(isPerfEnabled) {NSLog((@"|SKClient|P> %s(%d) " fmt), __FUNCTION__, __LINE__, ##__VA_ARGS__); }} while(0);
#define C(fmt, ...) do { if(isCryptDebugEnabled) {NSLog((@"|SKClient|C> %s(%d) " fmt), __FUNCTION__, __LINE__, ##__VA_ARGS__); }} while(0);

@implementation SKClient
@synthesize keyIDEnc, keyModEnc, keyExpEnc;
@synthesize keyIDEnc_TS, keyModEnc_TS, keyExpEnc_TS;
@synthesize isKeyInitiated;
@synthesize isKeyInitiatedTS;

#pragma mark -
#pragma mark 키 객체 초기화 관련

- (id) initWithUserDefaults {
    return [self initWithUserDefaults:NO];
}

- (id) initWithUserDefaults:(BOOL)enableDebug {
    self = [super init];
    if(self) {
        // initailization
        isDebugEnabled = enableDebug;
        isPerfEnabled = NO;
        isKeyInitiated = NO;
        isCryptDebugEnabled = NO;
        
        NSLog(@"---------------------------------");
        NSLog(@"%@ - %@, v%@", TAG, COPYRIGHT, _version);
        NSLog(@"---------------------------------");
        
        // 저장된 Key 로드
        if(![self loadKeyData]) {
            [self resetKeyData];
            
            self.keyIDEnc = [self encryptAES:DEFAULT_KEYID withKey:DEFAULT_STORE_SUPERKEY];
            self.keyModEnc = [self encryptAES:DEFAULT_PUBKEY_MOD withKey:DEFAULT_STORE_SUPERKEY];
            self.keyExpEnc = [self encryptAES:DEFAULT_PUBKEY_EXP withKey:DEFAULT_STORE_SUPERKEY];
            
            isKeyInitiated = NO;
            NSLog(@"No valid appKeyID found.");
            
        } else {
            
            isKeyInitiated = YES;
            
            NSString* keyID = [self decryptAES:self.keyIDEnc withKey:DEFAULT_STORE_SUPERKEY];
            NSString* keyMod = [self decryptAES:self.keyModEnc withKey:DEFAULT_STORE_SUPERKEY];
            NSString* keyExp = [self decryptAES:self.keyExpEnc withKey:DEFAULT_STORE_SUPERKEY];
            NSLog(@"keyID=%@, mod=%@, exp=%@", keyID, keyMod, keyExp);
        }
        
        // 저장된 Key 로드(발급서버용)
        if(![self loadKeyDataTS]) {
            [self resetKeyDataTS];
            
            self.keyIDEnc_TS = [self encryptAES:DEFAULT_KEYID withKey:DEFAULT_STORE_SUPERKEY];
            self.keyModEnc_TS = [self encryptAES:DEFAULT_PUBKEY_MOD withKey:DEFAULT_STORE_SUPERKEY];
            self.keyExpEnc_TS = [self encryptAES:DEFAULT_PUBKEY_EXP withKey:DEFAULT_STORE_SUPERKEY];
            
            isKeyInitiated = NO;
            NSLog(@"No valid appKeyID found.ts");
            
        } else {
            
            isKeyInitiated = YES;
            
            NSString* keyID_TS = [self decryptAES:self.keyIDEnc_TS withKey:DEFAULT_STORE_SUPERKEY];
            NSString* keyMod_TS = [self decryptAES:self.keyModEnc_TS withKey:DEFAULT_STORE_SUPERKEY];
            NSString* keyExp_TS = [self decryptAES:self.keyExpEnc_TS withKey:DEFAULT_STORE_SUPERKEY];
            NSLog(@"keyID_TS=%@, mod_TS=%@, exp_TS=%@", keyID_TS, keyMod_TS, keyExp_TS);
        }
    }
    return self;
}

- (id) initWithUserDefaultsTS {
    return [self initWithUserDefaultsTS:NO];
}

- (id) initWithUserDefaultsTS:(BOOL)enableDebug{
    self = [super init];
    if(self) {
        // initailization
        isDebugEnabled = enableDebug;
        isPerfEnabled = NO;
        isCryptDebugEnabled = NO;
        isKeyInitiatedTS = NO;
        
        NSLog(@"-----------------------------------------------");
        NSLog(@"%@[TCode server] - %@, v%@", TAG, COPYRIGHT, _version);
        NSLog(@"-----------------------------------------------");

        // 저장된 Key 로드
        if(![self loadKeyDataTS]) {
            [self resetKeyDataTS];
            
            self.keyIDEnc_TS = [self encryptAES:DEFAULT_KEYID withKey:DEFAULT_STORE_SUPERKEY];
            self.keyModEnc_TS = [self encryptAES:DEFAULT_PUBKEY_MOD withKey:DEFAULT_STORE_SUPERKEY];
            self.keyExpEnc_TS = [self encryptAES:DEFAULT_PUBKEY_EXP withKey:DEFAULT_STORE_SUPERKEY];
            
            L(@"No valid appKeyID found.");
            
            isKeyInitiatedTS = NO;
            
        } else {
            
            NSString* keyID_TS = [self decryptAES:self.keyIDEnc_TS withKey:DEFAULT_STORE_SUPERKEY];
            NSString* keyMod_TS = [self decryptAES:self.keyModEnc_TS withKey:DEFAULT_STORE_SUPERKEY];
            NSString* keyExp_TS = [self decryptAES:self.keyExpEnc_TS withKey:DEFAULT_STORE_SUPERKEY];
            L(@"keyID_TS=%@, mod_TS=%@, exp_TS=%@", keyID_TS, keyMod_TS, keyExp_TS);

            
            isKeyInitiatedTS = YES;
        }
    }
    return self;
}

- (BOOL) isKeyInitiated {
    return isKeyInitiated;
}

- (BOOL) isKeyInitiatedTS {
    return isKeyInitiatedTS;
}

- (BOOL) isRetentionKeyTS {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSDictionary *allDict = [defaults objectForKey:@"StorePublicKeyAtIndex1"];
    if (allDict != nil) {
        return YES;
    }
    return NO;
}

- (NSString*)encryptRsa:(NSString*)plainText {
    CkoRsa* rsa = [[[CkoRsa alloc] init] autorelease];
    BOOL success = [rsa UnlockComponent:UNLOCK_KEY];
    if(success != YES) {
        [NSException raise:@"Internal library error." format:@"Unlock component error..."];
        return nil;
    }
    
    NSString* keyMod = [self decryptAES:self.keyModEnc withKey:DEFAULT_STORE_SUPERKEY];
    NSString* keyExp = [self decryptAES:self.keyExpEnc withKey:DEFAULT_STORE_SUPERKEY];
    NSString* publicKey = [NSString stringWithFormat:@"<RSAKeyValue><Modulus>%@</Modulus><Exponent>%@</Exponent></RSAKeyValue>", keyMod, keyExp];
    [rsa ImportPublicKey:publicKey];
    
    rsa.EncodingMode = @"base64";
    
    NSString* ret = [rsa EncryptStringENC:plainText bUsePrivateKey:NO];
    return ret;
}

- (NSString*)encryptRsaTS:(NSString*)plainText {
    CkoRsa* rsa = [[[CkoRsa alloc] init] autorelease];
    BOOL success = [rsa UnlockComponent:UNLOCK_KEY];
    if(success != YES) {
        [NSException raise:@"Internal library error." format:@"Unlock component error..."];
        return nil;
    }
    
    NSString* keyMod = [self decryptAES:self.keyModEnc_TS withKey:DEFAULT_STORE_SUPERKEY];
    NSString* keyExp = [self decryptAES:self.keyExpEnc_TS withKey:DEFAULT_STORE_SUPERKEY];
    NSString* publicKey = [NSString stringWithFormat:@"<RSAKeyValue><Modulus>%@</Modulus><Exponent>%@</Exponent></RSAKeyValue>", keyMod, keyExp];
    [rsa ImportPublicKey:publicKey];
    
    rsa.EncodingMode = @"base64";
    
    NSString* ret = [rsa EncryptStringENC:plainText bUsePrivateKey:NO];
    return ret;
}

#pragma mark -
#pragma mark 발급 키 저장
- (BOOL) storePublicKey:(NSString*)keyID withKeyMod:(NSString*)mod withKeyExp:(NSString*)exp {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    
    self.keyIDEnc = [self encryptAES:keyID withKey:DEFAULT_STORE_SUPERKEY];
    self.keyModEnc = [self encryptAES:mod withKey:DEFAULT_STORE_SUPERKEY];
    self.keyExpEnc = [self encryptAES:exp withKey:DEFAULT_STORE_SUPERKEY];
    
    [defaults setObject:keyIDEnc forKey:SK_KEY_ID];
    [defaults setObject:keyModEnc forKey:SK_KEY_MOD];
    [defaults setObject:keyExpEnc forKey:SK_KEY_EXP];
    
    BOOL ret = [defaults synchronize];
    
    L(@"storePublicKey: appKeyID/MOD/EXP saved successfully!");

    return ret;
}

- (BOOL) storePublicKey:(NSString *)appKeyID {
    
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    
    self.keyIDEnc = [self encryptAES:appKeyID withKey:DEFAULT_STORE_SUPERKEY];
    
    [defaults setObject:keyIDEnc forKey:SK_KEY_ID];
    
    BOOL ret = [defaults synchronize];
    
    return ret;
}

#pragma mark - 
#pragma mark 발급키 저장(발급서버)
- (BOOL) storePublicKeyTS:(NSString*)tempAppKeyID withKeyModTS:(NSString*)mod withKeyExpTS:(NSString*)exp{
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
  
    self.keyIDEnc_TS = [self encryptAES:tempAppKeyID withKey:DEFAULT_STORE_SUPERKEY];
    self.keyModEnc_TS = [self encryptAES:mod withKey:DEFAULT_STORE_SUPERKEY];
    self.keyExpEnc_TS = [self encryptAES:exp withKey:DEFAULT_STORE_SUPERKEY];

    NSMutableDictionary *dict = [[[NSMutableDictionary alloc]initWithObjectsAndKeys:
               self.keyIDEnc_TS,SK_KEY_ID_TS,
               self.keyModEnc_TS,SK_KEY_MOD_TS,
               self.keyExpEnc_TS,SK_KEY_EXP_TS,
               nil]autorelease];

    [defaults setObject:dict forKey:@"StorePublicKeyAtIndex1"];
    
    BOOL ret = [defaults synchronize];
    
    L(@"storePublicKey_TS: appKeyID/MOD/EXP saved successfully!");
    
    isKeyInitiatedTS = YES;
    
    return ret;
}


#pragma mark -
#pragma mark 메시지 암복호화
- (NSString*) getAuthPayload:(NSString*)customerNumber {
    NSString* ret = nil;
    
    // Start timer
    NSTimeInterval startTime = [NSDate timeIntervalSinceReferenceDate];
    
    NSString* appID = [self getAppID];
    NSString* deviceID = [self getUniqueDeviceID];
    NSString* appIDEnc = [self encryptRsa:appID];
    
    NSDictionary* dictPayload = [NSDictionary dictionaryWithObjectsAndKeys:
                                 appIDEnc, @"appID",
                                 deviceID, @"deviceID", nil];
    
    ret = [self JSONRepresentation:dictPayload];
    
    // Stop timer
    NSTimeInterval endTime = [NSDate timeIntervalSinceReferenceDate];
    NSTimeInterval elapsedTime = (endTime - startTime) * 1000;
    P(@"Elapsed time in ms: %f", elapsedTime);
    
    return [self urlencode:ret];
}

- (NSDictionary *) getEncPayload:(NSString*)plain {
    // Start timer
    NSTimeInterval startTime = [NSDate timeIntervalSinceReferenceDate];
    
    NSString* keyID = [self decryptAES:self.keyIDEnc withKey:DEFAULT_STORE_SUPERKEY];
    NSString* accessToken = [self getAccessToken];

    NSDictionary* dictPayload = nil;
    
    if(plain != nil && ![plain isEqualToString:@""]) {
        dictPayload = [NSDictionary dictionaryWithObjectsAndKeys:
                       keyID, @"appKeyID",
                       accessToken, @"accessToken",
                       plain, @"encData",
                       nil];
    } else {
         dictPayload = [NSDictionary dictionaryWithObjectsAndKeys:
                        keyID, @"appKeyID",
                        accessToken, @"accessToken",
                        nil];
    }

    // Stop timer
    NSTimeInterval endTime = [NSDate timeIntervalSinceReferenceDate];
    NSTimeInterval elapsedTime = (endTime - startTime) * 1000;
    P(@"Elapsed time in ms: %f", elapsedTime);

    return dictPayload;
}

- (NSDictionary *) getEncPayloadTS:(NSString*)plain {
    // Start timer
    NSTimeInterval startTime = [NSDate timeIntervalSinceReferenceDate];
    NSLog(@"self.keyIDEnc_TS=%@", self.keyIDEnc_TS);
    NSString* keyID = [self decryptAES:self.keyIDEnc_TS withKey:DEFAULT_STORE_SUPERKEY];
    NSString* accessToken = [self getAccessTokenTS];
    NSString* encData = [self encryptAES:plain withKey:accessToken];
    
    NSLog(@"accessTokenTS=%@, encDataTS=%@", accessToken, encData);
    
    NSDictionary* dictPayload = nil;
    
    if(plain != nil && ![plain isEqualToString:@""]) {
        
        dictPayload = [NSDictionary dictionaryWithObjectsAndKeys:
        keyID, @"appKeyID",
        [self encryptRsaTS:accessToken], @"accessToken",
        encData, @"encData",
        nil];
        
    } else {
        
        dictPayload = [NSDictionary dictionaryWithObjectsAndKeys:
        keyID, @"appKeyID",
        [self encryptRsaTS:accessToken], @"accessToken",
        nil];
    }

    // Stop timer
    NSTimeInterval endTime = [NSDate timeIntervalSinceReferenceDate];
    NSTimeInterval elapsedTime = (endTime - startTime) * 1000;
    P(@"Elapsed time in ms: %f", elapsedTime);

    return dictPayload;
}

- (NSDictionary *) getEncPayloadTemp:(NSString*)plain {
    // Start timer
    NSTimeInterval startTime = [NSDate timeIntervalSinceReferenceDate];
    NSLog(@"self.keyIDEnc_TS=%@", self.keyIDEnc_TS);
    NSString* keyID = [self decryptAES:self.keyIDEnc_TS withKey:DEFAULT_STORE_SUPERKEY];
    NSString* accessToken = [self getAccessTokenTS];
    NSString* encData = [self encryptAES:plain withKey:accessToken];
    
    C(@"accessToken=%@, encDataTS=%@", accessToken, encData);
    
    NSDictionary* dictPayload = nil;
    
    if(plain != nil && ![plain isEqualToString:@""]) {
        
        dictPayload = [NSDictionary dictionaryWithObjectsAndKeys:
                       keyID, @"appKeyID",
                       accessToken, @"accessToken",
                       plain, @"encData",
                       nil];
        
    } else {
        
        dictPayload = [NSDictionary dictionaryWithObjectsAndKeys:
                       keyID, @"appKeyID",
                       accessToken, @"accessToken",
                       nil];
    }

    // Stop timer
    NSTimeInterval endTime = [NSDate timeIntervalSinceReferenceDate];
    NSTimeInterval elapsedTime = (endTime - startTime) * 1000;
    P(@"Elapsed time in ms: %f", elapsedTime);

    return dictPayload;
}

#pragma mark -
#pragma mark MISC.
- (void)setDebugEnabled:(BOOL)enabled {
    isDebugEnabled = enabled;
}

- (void)setPerfEnabled:(BOOL)enabled {
    isPerfEnabled = enabled;
}

- (void)setProp:(NSString*)key withValue:(NSString*)value {
    if([key isEqualToString:@"cryptDebug"]) {
        if([value isEqualToString:@"true"]) {
            isCryptDebugEnabled = YES;
        }
    }
}

- (NSString*)getProp:(NSString*)key {
    NSString* ret = nil;
    
    if([key isEqualToString:@"version"]) {
        
        //--------------
        // 버전 정보
        //--------------
        ret = [self getVersion];
        
    } else if([key isEqualToString:@"appID"]) {
        
        //--------------
        // appID
        //--------------
        NSString* appID = [self getAppID];
        
        C(@"appID=[%@]", appID);
        NSLog(@"appID=[%@]", appID);
        
        CkoRsa* rsa = [[[CkoRsa alloc] init] autorelease];
        BOOL success = [rsa UnlockComponent:UNLOCK_KEY];
        if(success != YES) {
            [NSException raise:@"Internal library error." format:@"Unlock component error..."];
            return nil;
        }
        
        NSString* keyMod = DEFAULT_PUBKEY_MOD;
        NSString* keyExp = DEFAULT_PUBKEY_EXP;
        NSString* publicKey = [NSString stringWithFormat:@"<RSAKeyValue><Modulus>%@</Modulus><Exponent>%@</Exponent></RSAKeyValue>", keyMod, keyExp];
        [rsa ImportPublicKey:publicKey];
        
        rsa.EncodingMode = @"base64";
        
        NSString* enc = [rsa EncryptStringENC:appID bUsePrivateKey:NO];
        if(enc == nil) {
            P(@"appID=[%@]", appID);
            ret = @"";
        } else {
            ret = [NSString stringWithString:enc];
        }
        
    } else if([key isEqualToString:@"appKeyID"]) {
        
        //--------------
        // appKeyID
        //--------------
        if( self.keyIDEnc ) {
            
            C(@"keyIDEnc=%@", self.keyIDEnc);
            C(@"keyModEnc=%@", self.keyModEnc);
            C(@"keyExpEnc=%@", self.keyExpEnc);
            
            ret = [self decryptAES:self.keyIDEnc withKey:DEFAULT_STORE_SUPERKEY];
        } else {
            ret = @"1";
        }
        
    }
    NSLog(@"ret===%@", ret);
    return ret;
}

- (NSString*)getVersion {
    return _version;
}

#pragma mark -
#pragma mark Private
- (BOOL) loadKeyData {
    NSUserDefaults* defaults = [NSUserDefaults standardUserDefaults];
    self.keyIDEnc = [defaults stringForKey:SK_KEY_ID];
    self.keyModEnc = [defaults stringForKey:SK_KEY_MOD];
    self.keyExpEnc = [defaults stringForKey:SK_KEY_EXP];
            
    return (self.keyIDEnc) && (self.keyModEnc) && (self.keyExpEnc);
}

- (BOOL) loadKeyDataTS {
    NSUserDefaults* defaults = [NSUserDefaults standardUserDefaults];
    NSDictionary *dict = [defaults objectForKey:@"StorePublicKeyAtIndex1"];
    if (dict != nil) {
        self.keyIDEnc_TS = [dict objectForKey:SK_KEY_ID_TS];
        self.keyModEnc_TS = [dict objectForKey:SK_KEY_MOD_TS];
        self.keyExpEnc_TS = [dict objectForKey:SK_KEY_EXP_TS];
    } else {
        return NO;
    }

    return (self.keyIDEnc_TS) && (self.keyModEnc_TS) && (self.keyExpEnc_TS);
}

- (BOOL) resetKeyData {
    NSUserDefaults* defaults = [NSUserDefaults standardUserDefaults];
    [defaults removeObjectForKey:SK_KEY_ID];
    [defaults removeObjectForKey:SK_KEY_MOD];
    [defaults removeObjectForKey:SK_KEY_EXP];
    
    L(@"storePublicKey: appKeyID/MOD/EXP cleared.");
    
    return [defaults synchronize];
}

- (BOOL) resetKeyDataTS {
    NSUserDefaults* defaults = [NSUserDefaults standardUserDefaults];

    NSDictionary *dict = [defaults objectForKey:@"StorePublicKeyAtIndex1"];
    if (dict != nil) {
        self.keyExpEnc_TS = [dict objectForKey:SK_KEY_ID_TS];
        self.keyModEnc_TS = [dict objectForKey:SK_KEY_MOD_TS];
        self.keyExpEnc_TS = [dict objectForKey:SK_KEY_EXP_TS];
    } else {
        return NO;
    }
    
    L(@"storePublicKeyTS: appKeyID/MOD/EXP cleared.");
    
    return [defaults synchronize];
}

//기존에 아이피로 저장했던 키 값이 있다면 'StorePublicKeyAtIndex1' 이름으로 재 저장
- (void)migrationKey:(NSString *)ip {

    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSDictionary *dict = [defaults objectForKey:ip];
    if (dict) {
        [defaults setObject:dict forKey:@"StorePublicKeyAtIndex1"];
        [defaults removeObjectForKey:ip];
        [defaults synchronize];
    }
}

- (NSString*) getAppID {

    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
    dateFormatter.dateFormat = @"yyyy'S'MM'R'dd'P'HH'A'mm'Y'ss";
    [dateFormatter setTimeZone:[NSTimeZone timeZoneWithName:@"Asia/Seoul"]];
    [dateFormatter setLocale:[[NSLocale alloc] initWithLocaleIdentifier:@"ko_KR"]];
    NSTimeZone *gmt = [NSTimeZone timeZoneWithAbbreviation:@"GMT"];
    [dateFormatter setTimeZone:gmt];
    NSString *timeStamp = [dateFormatter stringFromDate:[NSDate dateWithTimeIntervalSinceNow:32400]]; //GMT+9
    return timeStamp;
}

- (NSString*) getAccessToken {
    NSString* ret = nil;
    
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    [formatter setTimeZone:[NSTimeZone timeZoneWithName:@"Asia/Seoul"]];
    [formatter setLocale:[[NSLocale alloc] initWithLocaleIdentifier:@"ko_KR"]];
    [formatter setDateFormat:@"yyyyMMddHHmmss"];
    
    NSTimeZone *gmt = [NSTimeZone timeZoneWithAbbreviation:@"GMT"];
    [formatter setTimeZone:gmt];
    NSString *postfix = [formatter stringFromDate:[NSDate dateWithTimeIntervalSinceNow:32400]]; //GMT+9

    NSString* keyIDWithPadding = [[self decryptAES:self.keyIDEnc withKey:DEFAULT_STORE_SUPERKEY] stringByPaddingToLength:17 withString:@" " startingAtIndex:0];
    ret = [[[NSString stringWithFormat:@"%@", keyIDWithPadding] stringByAppendingString:@"_" ] stringByAppendingString:postfix];
       
    return ret;
}

- (NSString*) getAccessTokenTS {
    NSString* ret = nil;
    
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    [formatter setTimeZone:[NSTimeZone timeZoneWithName:@"Asia/Seoul"]];
    [formatter setLocale:[[NSLocale alloc] initWithLocaleIdentifier:@"ko_KR"]];
    [formatter setDateFormat:@"yyyyMMddHHmmss"];
    
    NSTimeZone *gmt = [NSTimeZone timeZoneWithAbbreviation:@"GMT"];
    [formatter setTimeZone:gmt];
    NSString *postfix = [formatter stringFromDate:[NSDate dateWithTimeIntervalSinceNow:32400]]; //GMT+9

    NSString* keyIDWithPadding = [[self decryptAES:self.keyIDEnc_TS withKey:DEFAULT_STORE_SUPERKEY] stringByPaddingToLength:17 withString:@" " startingAtIndex:0];
    ret = [[[NSString stringWithFormat:@"%@", keyIDWithPadding] stringByAppendingString:@"_" ] stringByAppendingString:postfix];
        
    return ret;
}

- (NSString *)getSessionKeyIsSign:(BOOL)isSign {
    NSString *ret = nil;
    NSString *accessToken = nil;
    
    if (isSign) {
        accessToken = [self getAccessTokenTS];
    }
    else {
        accessToken = [self getAccessToken];
    }
    
    NSArray *comp1 = [accessToken componentsSeparatedByString:@"_"];
    
    NSString *str1 = [comp1 objectAtIndex:0];
    NSString *str2 = [comp1 objectAtIndex:1];
    
    NSString *first = [str1 substringFromIndex:str1.length-8];
    NSString *last = [str2 substringFromIndex:str2.length-8];
    
    ret = [NSString stringWithFormat:@"%@%@", first, last];
    
    return ret;
}

- (NSString*) getUniqueDeviceID {
    NSString* ret = nil;
    
    ret = [self uniqueGlobalDeviceIdentifier];
    
    return ret;
}

- (NSString *)urlencode: (NSString *) url {
    NSString* enc = (NSString*)CFURLCreateStringByAddingPercentEscapes(NULL, (CFStringRef)url, NULL, (CFStringRef)@"!*'\"{}();:@&=+$,/?%#[]%", CFStringConvertNSStringEncodingToEncoding(0x80000000 + kCFStringEncodingDOSKorean));
    return enc;
}

- (NSString*)encryptAES:(NSString*)orgString {
    return [self encryptAES:orgString withKey:DEFAULT_SUPERKEY];
}

- (NSString*)encryptAES:(NSString*)orgString withKey:(NSString*)key {
    NSData* orgData = [orgString dataUsingEncoding:NSUTF8StringEncoding];
    NSString* encString = [SKClient encodeBase64WithData:[orgData AESEncryptWithKey:key]];
    return encString;
}

- (NSString*)decryptAES:(NSString*)encString {
    return [self decryptAES:encString withKey:DEFAULT_SUPERKEY];
}

- (NSString*)decryptAES:(NSString*)encString withKey:(NSString*)key {
    NSData* encData = [SKClient decodeBase64WithString:encString];
    NSData* decData = [encData AESDecryptWithKey:key];
    NSString* decString = [[[NSString alloc] initWithData:decData encoding:NSUTF8StringEncoding] autorelease];
    return decString;
}

- (NSString*)encryptWithTranKey:(NSString*)plainString {
    return [self encryptRsa:plainString];
}

#pragma mark -
#pragma mark Base64

+ (NSString *)encodeBase64WithString:(NSString *)strData {
    return [SKClient encodeBase64WithData:[strData dataUsingEncoding:NSUTF8StringEncoding]];
}

+ (NSString *)encodeBase64WithData:(NSData *)objData {
    const unsigned char * objRawData = [objData bytes];
    char * objPointer;
    char * strResult;
    
    // Get the Raw Data length and ensure we actually have data
    int intLength = (int)[objData length];
    if (intLength == 0) return nil;
    
    // Setup the String-based Result placeholder and pointer within that placeholder
    strResult = (char *)calloc((((intLength + 2) / 3) * 4) + 1, sizeof(char));
    objPointer = strResult;
    
    // Iterate through everything
    while (intLength > 2) { // keep going until we have less than 24 bits
        *objPointer++ = _base64EncodingTable[objRawData[0] >> 2];
        *objPointer++ = _base64EncodingTable[((objRawData[0] & 0x03) << 4) + (objRawData[1] >> 4)];
        *objPointer++ = _base64EncodingTable[((objRawData[1] & 0x0f) << 2) + (objRawData[2] >> 6)];
        *objPointer++ = _base64EncodingTable[objRawData[2] & 0x3f];
        
        // we just handled 3 octets (24 bits) of data
        objRawData += 3;
        intLength -= 3;
    }
    
    // now deal with the tail end of things
    if (intLength != 0) {
        *objPointer++ = _base64EncodingTable[objRawData[0] >> 2];
        if (intLength > 1) {
            *objPointer++ = _base64EncodingTable[((objRawData[0] & 0x03) << 4) + (objRawData[1] >> 4)];
            *objPointer++ = _base64EncodingTable[(objRawData[1] & 0x0f) << 2];
            *objPointer++ = '=';
        } else {
            *objPointer++ = _base64EncodingTable[(objRawData[0] & 0x03) << 4];
            *objPointer++ = '=';
            *objPointer++ = '=';
        }
    }
    
    // Terminate the string-based result
    *objPointer = '\0';
    
    // Create result NSString object
    NSString *base64String = [NSString stringWithCString:strResult encoding:NSASCIIStringEncoding];
    
    // Free memory
    free(strResult);
    
    return base64String;
}

+ (NSData *)decodeBase64WithString:(NSString *)strBase64 {
    const char *objPointer = [strBase64 cStringUsingEncoding:NSASCIIStringEncoding];
    size_t intLength = strlen(objPointer);
    int intCurrent;
    int i = 0, j = 0, k;
    
    unsigned char *objResult = calloc(intLength, sizeof(unsigned char));
    
    // Run through the whole string, converting as we go
    while ( ((intCurrent = *objPointer++) != '\0') && (intLength-- > 0) ) {
        if (intCurrent == '=') {
            if (*objPointer != '=' && ((i % 4) == 1)) {// || (intLength > 0)) {
                // the padding character is invalid at this point -- so this entire string is invalid
                free(objResult);
                return nil;
            }
            continue;
        }
        
        intCurrent = _base64DecodingTable[intCurrent];
        if (intCurrent == -1) {
            // we're at a whitespace -- simply skip over
            continue;
        } else if (intCurrent == -2) {
            // we're at an invalid character
            free(objResult);
            return nil;
        }
        
        switch (i % 4) {
            case 0:
                objResult[j] = intCurrent << 2;
                break;
                
            case 1:
                objResult[j++] |= intCurrent >> 4;
                objResult[j] = (intCurrent & 0x0f) << 4;
                break;
                
            case 2:
                objResult[j++] |= intCurrent >>2;
                objResult[j] = (intCurrent & 0x03) << 6;
                break;
                
            case 3:
                objResult[j++] |= intCurrent;
                break;
        }
        i++;
    }
    
    // mop things up if we ended on a boundary
    k = j;
    if (intCurrent == '=') {
        switch (i % 4) {
            case 1:
                // Invalid state
                free(objResult);
                return nil;
                
            case 2:
                k++;
                // flow through
            case 3:
                objResult[k] = 0;
        }
    }
    
    // Cleanup and setup the return NSData
    NSData * objData = [[[NSData alloc] initWithBytes:objResult length:j] autorelease];
    free(objResult);
    return objData;
}

#pragma mark -
#pragma mark SHA256
- (NSString*) SHA256:(NSString*)str withEncType:(NSString *)type withAuthID:(NSString*)authID{
    const char *cstr = [str cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:str.length];
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    
    CC_SHA256(data.bytes, (uint32_t)data.length, digest);
    
    if ([@"B"isEqualToString:type]) {
        NSMutableData *data=[NSMutableData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
        [data appendData:[authID dataUsingEncoding:NSUTF8StringEncoding]];
        return [SKClient encodeBase64WithData:data];
        
    }else if([@"E"isEqualToString:type]){
        NSMutableData *data=[NSMutableData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
        [data appendData:[authID dataUsingEncoding:NSUTF8StringEncoding]];
        return [data ascii85EncodedString];
        
    }else if([@"H"isEqualToString:type]){
        NSData* data = [NSData dataWithBytes:(const void*)digest length:CC_SHA256_DIGEST_LENGTH]; //32
        NSData *data2 = [authID dataUsingEncoding:NSUTF8StringEncoding]; //16
        data = [data subdataWithRange:NSMakeRange(0,data.length - data2.length)];
        
        NSMutableData *mData = [NSMutableData dataWithData:data];
        [mData appendData:data2];
        
        return [self dataToHexString:mData];
        
    }else {
        NSLog(@"Error.. Unknown EncType..");
        return @"";
    }
    return @"";
}

#pragma mark
#pragma mark HEX
- (NSString *)intToHex :(int)time{
    NSString *hex = [NSString stringWithFormat:@"%02X", time];
    return hex;
}

- (NSString *)dataToHexString:(NSData *)data {
    const unsigned char *dataBuffer = (const unsigned char *)[data bytes];
    if (!dataBuffer) return [NSString string];
    NSUInteger dataLength  = [data length];
    NSMutableString *hexString  = [NSMutableString stringWithCapacity:(dataLength * 2)];
    for (int i = 0; i < dataLength; ++i) {
        [hexString appendString:[NSString stringWithFormat:@"%02lx", (unsigned long)dataBuffer[i]]];
    }
    return [NSString stringWithString:hexString];
}


#pragma mark - 
#pragma mark UDID replacement
- (NSString *) uniqueDeviceIdentifier{
    NSString *macaddress = [self macaddress];
    NSString *bundleIdentifier = [[NSBundle mainBundle] bundleIdentifier];
    
    NSString *stringToHash = [NSString stringWithFormat:@"%@%@",macaddress,bundleIdentifier];
    NSString *uniqueIdentifier = [self stringFromMD5:stringToHash];
    
    return uniqueIdentifier;
}

- (NSString *) uniqueGlobalDeviceIdentifier{
    NSString *macaddress = [self macaddress];
    NSString *uniqueIdentifier = [self stringFromMD5:macaddress];
    
    return uniqueIdentifier;
}


// Return the local MAC addy
// Courtesy of FreeBSD hackers email list
// Accidentally munged during previous update. Fixed thanks to erica sadun & mlamb.
- (NSString *) macaddress{
    
    int                 mib[6];
    size_t              len;
    char                *buf;
    unsigned char       *ptr;
    struct if_msghdr    *ifm;
    struct sockaddr_dl  *sdl;
    
    mib[0] = CTL_NET;
    mib[1] = AF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_LINK;
    mib[4] = NET_RT_IFLIST;
    
    if ((mib[5] = if_nametoindex("en0")) == 0) {
        printf("Error: if_nametoindex error\n");
        return NULL;
    }
    
    if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) {
        printf("Error: sysctl, take 1\n");
        return NULL;
    }
    
    if ((buf = malloc(len)) == NULL) {
        printf("Could not allocate memory. error!\n");
        return NULL;
    }
    
    if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
        printf("Error: sysctl, take 2");
        free(buf);
        return NULL;
    }
    
    ifm = (struct if_msghdr *)buf;
    sdl = (struct sockaddr_dl *)(ifm + 1);
    ptr = (unsigned char *)LLADDR(sdl);
    NSString *outstring = [NSString stringWithFormat:@"%02X:%02X:%02X:%02X:%02X:%02X",
                           *ptr, *(ptr+1), *(ptr+2), *(ptr+3), *(ptr+4), *(ptr+5)];
    free(buf);
    
    return outstring;
}

- (NSString *) stringFromMD5:(NSString*)str {
    
    if(str == nil || [str length] == 0)
        return nil;
    
    const char *value = [str UTF8String];
    
    unsigned char outputBuffer[CC_MD5_DIGEST_LENGTH];
    CC_MD5(value, (int)strlen(value), outputBuffer);
    
    NSMutableString *outputString = [[NSMutableString alloc] initWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for(NSInteger count = 0; count < CC_MD5_DIGEST_LENGTH; count++){
        [outputString appendFormat:@"%02x",outputBuffer[count]];
    }
    
    return [outputString autorelease];
}

#pragma mark -
#pragma mark JSON

- (NSString *)JSONRepresentation:(NSObject*)obj {
    SKC_SBJsonWriter *writer = [[[SKC_SBJsonWriter alloc] init] autorelease];
    NSString *json = [writer stringWithObject:obj];
    if (!json)
        L(@"-JSONRepresentation failed. Error is: %@", writer.error);
    return json;
}

#pragma mark -
#pragma mark 스마트 장치인증 관련
- (NSDictionary *)getEncPayloadForGetAuthID:(NSString *)tc withScreenType:(NSString *)screenType withAuthType:(NSString*)authType  {
    
    /* -------------------------------------------------
     os           디바이스 타입 ('02':iOS, '01':android)
     ifv          장치식별자
     bundleName   bundle indentifier
     tranDate     인증요청시간
     tc           통신사(1: 2: 3: 4: 5: 6:)
     deviceModel  기기모델명
     screenType   요청타입(J:신규/재가입, P:결제)
     authType     인증구분값(0:앱안심인증 , 1:소지인증 only)
     canSendSms   SMS발송 가능여부(Y:가능 N:불가)
     --------------------------------------------------*/
    
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    
    NSString *os = @"02";
    NSString *ifv = @"";
    NSString *tranDate = @"";
    
    struct utsname u;
    uname(&u);
    NSString *deviceModel = [NSString stringWithFormat:@"%s",u.machine];
    NSString *osVersion = [NSString stringWithFormat:@"%f", [[[UIDevice currentDevice] systemVersion] floatValue]];
    NSString *model = [NSString stringWithFormat:@"%@;%@",deviceModel,osVersion];
    NSString *bundleName = [[NSBundle mainBundle] bundleIdentifier];
    if (bundleName.length >23) {
        bundleName = [bundleName substringToIndex:23];
    }
    
    NSDateFormatter *formatter = [[[NSDateFormatter alloc]init]autorelease];
    [formatter setTimeZone:[NSTimeZone timeZoneWithName:@"Asia/Seoul"]];
    [formatter setLocale:[[NSLocale alloc] initWithLocaleIdentifier:@"ko_KR"]];
    [formatter setDateFormat:@"yyyyMMddHHmmssSSS"];
    
    NSTimeZone *gmt = [NSTimeZone timeZoneWithAbbreviation:@"GMT"];
    [formatter setTimeZone:gmt];
    tranDate = [formatter stringFromDate:[NSDate dateWithTimeIntervalSinceNow:32400]]; //GMT+9
    
    [defaults setObject:tranDate forKey:SK_POSSESION_TRANDATE];
    
    NSString *originIfv = [[[UIDevice currentDevice] identifierForVendor] UUIDString];
    NSArray *strArray = [originIfv componentsSeparatedByString:@"-"];
    
    for ( NSString* thisElement in strArray ) {
        ifv = [ifv stringByAppendingString:[NSString stringWithFormat:@"%@",thisElement] ];
    }
    
    if ([@""isEqualToString:ifv]) {
        NSLog(@"ERROR.. getEncPayloadForGetAuthID : [ ifv is NULL ]");
        return nil;
        
    } else if([@""isEqualToString:tranDate]) {
        NSLog(@"ERROR.. getEncPayloadForGetAuthID : [ tranDate is NULL ]");
        return nil;
        
    } else if([@"" isEqualToString:bundleName]) {
        NSLog(@"ERROR.. getEncPayloadForGetAuthID : [ bundleName is NULL ]");
        return nil;
    }
    
    NSString *canSendSms = @"N";
    if([self isCanSendMessage]) {
        canSendSms = @"Y";
    }
    
    NSMutableDictionary *d = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                       os,@"os",
                       tranDate,@"tranDate",
                       ifv, @"ifv",
                       bundleName, @"bundleName",
                       model, @"deviceModel",
                       tc, @"tc",
                       screenType, @"screenType",
                       authType, @"authType",
                       canSendSms, @"canSendSms",
                       nil];
    return d;
}

- (BOOL)isCanSendMessage {
    BOOL isTelOpen = [[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"tel://"]];
    BOOL isSendMsg = [MFMessageComposeViewController canSendText];
    BOOL isiPad = YES;
    BOOL isUSIM = YES;
    
    NSString* modelName = [[UIDevice currentDevice] model];
    NSRange search = [modelName rangeOfString:@"Pad"];
    
    if (search.length > 0) {
        isiPad = NO;
    }
    
    //USIM 체크
    CTTelephonyNetworkInfo* info = [[CTTelephonyNetworkInfo alloc] init];
    CTCarrier* carrier = info.subscriberCellularProvider;
    NSString *mcc = carrier.mobileCountryCode;
    NSString *mnc = carrier.mobileNetworkCode;
    if ([mcc length] == 0 || [mnc length] == 0) {
        isUSIM = NO;
    }
    
    
    return isTelOpen && isSendMsg && isiPad && isUSIM;
}

- (void) sendSMS:(UIViewController *)view withAuthID:(NSString*)authID withExtra:(NSString *)ext withSendPhone:(NSString*)sendPhone withEncMode:(NSString *)mode
{
    /* -------------------------------------------------
     sendPhone   SMS송신번호
     view        SMS발송 컨트롤러를 띄울 화면
     --------------------------------------------------*/
    
    self.view = view;
    
    if([MFMessageComposeViewController canSendText]){
        if (self.mfmController == nil){
            self.mfmController= [[MFMessageComposeViewController alloc] init];
        }
        
        NSString *body = [self makeHashData:mode withAuthID:authID];
        
        self.mfmController.messageComposeDelegate = self;
        self.mfmController.body = [NSString stringWithFormat:@"%@ %@",ext,body];
        self.mfmController.recipients = [NSArray arrayWithObjects:sendPhone,nil];
        
        [self performSelector:@selector(showSMS:) withObject:view afterDelay:0.7];
    }
}

- (void)showSMS:(UIViewController *) cont{
    [cont presentViewController:self.mfmController animated:YES completion:^{
        [[UIApplication sharedApplication] setStatusBarStyle:UIStatusBarStyleBlackTranslucent];
    }];
    
    [self performSelector:@selector(hidePhoneNumber) withObject:nil afterDelay:0.5];
}

- (void)hidePhoneNumber{
    if (self.dummy != nil) {
        [self.dummy release];
        self.dummy = nil;
    }
    
    self.dummy = [[UIView alloc]initWithFrame:CGRectMake(0,64, self.view.view.frame.size.width, 45)];
    self.dummy.backgroundColor = [UIColor whiteColor];
    self.dummy.alpha = 0.1;
    [[[UIApplication sharedApplication] delegate].window addSubview:self.dummy];
}

- (NSString *)makeHashData :(NSString *)mode withAuthID:(NSString *)authID{
    
    NSString *bundleName = [[NSBundle mainBundle] bundleIdentifier];
    
    if (bundleName.length >23) {
        bundleName = [bundleName substringToIndex:23];
    }
    
    NSString *originIfv = [[[UIDevice currentDevice] identifierForVendor] UUIDString];
    NSString *ifv = @"";
    NSArray *ifvArray = [originIfv componentsSeparatedByString:@"-"];
    for ( NSString* thisElement in ifvArray ) {
        ifv = [ifv stringByAppendingString:[NSString stringWithFormat:@"%@",thisElement] ];
    }
    
    NSString *stamp = [self getCurrentTimeStamp];
    
    if([[NSNull null]isEqual:stamp] || [@""isEqualToString:stamp]) {
        NSLog(@"ERROR.. sendSMS : [ unix timestamp is NULL ]");
        return @"";
    }
    
    int iStamp = [stamp intValue];
    NSString *hexStamp = [self intToHex:iStamp];
    hexStamp = [hexStamp lowercaseString];
    
    NSString *hashString = [NSString stringWithFormat:@"%@%@%@%@", @"I",ifv,bundleName,hexStamp];
    NSString *result = [self SHA256:hashString withEncType:mode withAuthID:authID];
    
    return result;
}

- (NSString *)getCurrentTimeStamp{
    
    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
    [dateFormatter setTimeZone:[NSTimeZone timeZoneWithName:@"Asia/Seoul"]];
    [dateFormatter setLocale:[[NSLocale alloc] initWithLocaleIdentifier:@"ko_KR"]];
    [dateFormatter setDateFormat:@"yyyyMMddHHmmssSSS"];
    
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *tranDate = [defaults stringForKey:SK_POSSESION_TRANDATE];
    
    NSDate *date = [[[NSDate alloc]init]autorelease];
    date = [dateFormatter dateFromString:tranDate];
    
    int millisecondsInt = (int)([date timeIntervalSince1970]);
    NSString *strTimeStamp = [NSString stringWithFormat:@"%d",millisecondsInt];
    
    return strTimeStamp;
}

- (void)removeTimeStame {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    [defaults setObject:@"" forKey:SK_POSSESION_TRANDATE];
}

- (void)messageComposeViewController:(MFMessageComposeViewController *)controller didFinishWithResult:(MessageComposeResult)result {
    
    NSString *resultSMS = @"N";
    
    if (result == MessageComposeResultCancelled) {
        resultSMS = @"N";
        NSLog(@"발송 취소..");
        
    } else if (result == MessageComposeResultFailed){
        resultSMS = @"F";
        NSLog(@"발송 실패..");
        
    } else if (result == MessageComposeResultSent) {
        resultSMS = @"S";
        NSLog(@"발송 성공!!");
        
    } else {
        resultSMS = @"F";
        NSLog(@"기타 발송 오류..");
    }
    
    [self.delegate resultSendSMS:resultSMS];

    [self.dummy removeFromSuperview];
    [self.dummy release];
    self.dummy = nil;
    
    [self.mfmController dismissViewControllerAnimated:YES completion:nil];
    [self.mfmController release];
    self.mfmController = nil;
}

- (void)resultSendSMS:(NSString *)result {
    
}

@end
