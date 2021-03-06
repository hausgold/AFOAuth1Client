// AFOAuth1RequestSerializer.h
//  
// Copyright (c) 2011-2014 AFNetworking (http://afnetworking.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import <AFNetworking/AFURLRequestSerialization.h>
#import <AFOAuth1Client/AFOAuth1Token.h>

NS_ASSUME_NONNULL_BEGIN

/**
 Signature method enumeration/
 */
typedef NS_ENUM(NSUInteger, AFOAuth1SignatureMethod) {
    /**
     PLAINTEXT signature method.
     */
    AFOAuth1PlainTextSignatureMethod = 1,
    /**
     HMAC-SHA1 signature method.
     */
    AFOAuth1HMACSHA1SignatureMethod = 2,
};

@interface AFOAuth1RequestSerializer : AFHTTPRequestSerializer

///-----------------------------------
/// @name Managing OAuth Configuration
///-----------------------------------

/**
 The method used to create an OAuth signature. `AFPlainTextSignatureMethod` by default.
 */
@property (nonatomic, assign) AFOAuth1SignatureMethod signatureMethod;

/**
 The authentication realm.
 */
@property (nonatomic, copy, nullable) NSString *realm;

/**
 The client's access token.
 */
@property (nonatomic, strong, nullable) AFOAuth1Token *accessToken;

/**
 OAuth parameters.
 */
@property (nonatomic, copy, readonly, nullable) NSDictionary *oauthParameters;

/**
 Creates and initializes an `AFOAuth1RequestSerializer` object with the specified key, and secret.
 
 @param key The client key.
 @param secret The client secret.
 */
+ (instancetype)serializerWithKey:(NSString *)key secret:(NSString *)secret;

/**
 Instantiates an `AFOAuth1RequestSerializer` object with the specified key, and secret.
 
 @param key The client key.
 @param secret The client secret.
 */
- (instancetype)initWithKey:(NSString *)key secret:(NSString *)secret NS_DESIGNATED_INITIALIZER;

@end

NS_ASSUME_NONNULL_END
