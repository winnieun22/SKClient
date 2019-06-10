//
//  SKClient.h
//  SKClient
//
//  Created by 박지웅 on 13. 2. 12..
//  Copyright (c) 2013년 Seeroo Information Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <MessageUI/MFMessageComposeViewController.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <CoreTelephony/CTCarrier.h>

@interface SKClient : NSObject <MFMessageComposeViewControllerDelegate>
{
    BOOL isDebugEnabled;
    BOOL isPerfEnabled;
    BOOL isKeyInitiated;
    BOOL isCryptDebugEnabled;
    BOOL isKeyInitiatedTS;
    
    NSString* keyIDEnc;
    NSString* keyModEnc;
    NSString* keyExpEnc;
    
    NSString* keyIDEnc_TS;
    NSString* keyModEnc_TS;
    NSString* keyExpEnc_TS;
};

@property (retain, nonatomic) MFMessageComposeViewController *mfmController;
@property (retain, nonatomic) UIViewController *view;
@property (retain, nonatomic) id delegate;

@property (readonly) BOOL isKeyInitiated;
@property (nonatomic, retain) NSString* keyIDEnc;
@property (nonatomic, retain) NSString* keyModEnc;
@property (nonatomic, retain) NSString* keyExpEnc;

@property (nonatomic, retain) NSString* keyIDEnc_TS;
@property (nonatomic, retain) NSString* keyModEnc_TS;
@property (nonatomic, retain) NSString* keyExpEnc_TS;

@property (nonatomic, retain) NSMutableDictionary *dictEncKey;
@property (readonly) BOOL isKeyInitiatedTS;

@property (retain, nonatomic) UIView *dummy;

#pragma mark -
#pragma mark 키 객체 초기화 관련
- (id) initWithUserDefaults;
- (id) initWithUserDefaults:(BOOL)enableDebug;
- (BOOL) isKeyInitiated;
- (BOOL) isKeyInitiatedTS;

#pragma mark -
#pragma mark 키 객체 초기화 관련(발급서버)
- (id) initWithUserDefaultsTS;
- (id) initWithUserDefaultsTS:(BOOL)enableDebug;

#pragma mark -
#pragma mark 발급 키 저장
- (BOOL) storePublicKey:(NSString*)keyID withKeyMod:(NSString*)mod withKeyExp:(NSString*)exp;
- (BOOL) storePublicKey:(NSString *)appKeyID;

#pragma mark -
#pragma mark 발급 키 저장(발급서버)
- (BOOL) storePublicKeyTS:(NSString*)tempAppKeyID withKeyModTS:(NSString*)mod withKeyExpTS:(NSString*)exp;
- (void) migrationKey:(NSString *)ip;

#pragma mark -
#pragma mark 메시지 암복호화
- (NSString*) getAuthPayload:(NSString*)customerNumber;
- (NSDictionary*) getEncPayload:(NSString*)plain;

#pragma mark -
#pragma mark 메시지 암복호화(발급서버)
- (NSDictionary *) getEncPayloadTS:(NSString*)plain;

#pragma mark -
#pragma mark 메시지 암복호화(임시값)
- (NSDictionary *) getEncPayloadTemp:(NSString*)plain;

#pragma mark -
#pragma mark MISC.
- (void)setDebugEnabled:(BOOL)enabled;
- (void)setPerfEnabled:(BOOL)enabled;
- (NSString*)getVersion;
- (NSString*)getProp:(NSString*)key;
- (void)setProp:(NSString*)key withValue:(NSString*)value;

#pragma mark -
#pragma mark Utilities
- (NSString*)encryptAES:(NSString*)orgString;
- (NSString*)decryptAES:(NSString*)encString;
- (NSString*)encryptWithTranKey:(NSString*)plainString;

+ (NSString *)encodeBase64WithString:(NSString *)strData;
+ (NSString *)encodeBase64WithData:(NSData *)objData;
+ (NSData *)decodeBase64WithString:(NSString *)strBase64;

- (NSString *)getSessionKeyIsSign:(BOOL)isSign;

- (BOOL) loadKeyDataTS;//키가져오기
- (BOOL) resetKeyDataTS; //키초기화
- (BOOL) isRetentionKeyTS; //키있나없나확인

- (void)removeTimeStame;

#pragma mark -
#pragma mark Smart Authentication
- (NSDictionary *)getEncPayloadForGetAuthID:(NSString *)tc withScreenType:(NSString *)screenType withAuthType:(NSString*)authType;
- (BOOL)isCanSendMessage;
- (void) sendSMS:(UIViewController *)view withAuthID:(NSString*)authID withExtra:(NSString *)ext withSendPhone:(NSString*)sendPhone withEncMode:(NSString *)mode;
- (void)resultSendSMS:(NSString *)result;

@end
