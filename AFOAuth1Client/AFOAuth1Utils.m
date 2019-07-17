// AFOAuth1Utils.m
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

#import <CommonCrypto/CommonHMAC.h>
#import "AFOAuth1Utils.h"

NSString * AFOAuth1Nounce() {
    CFUUIDRef uuid = CFUUIDCreate(NULL);
    CFStringRef string = CFUUIDCreateString(NULL, uuid);
    CFRelease(uuid);
    return (NSString *)CFBridgingRelease(string);
}

/**
 Returns a percent-escaped string for a header string key or value.
 RFC 3986 states that the following characters are "reserved" characters.
 - General Delimiters: ":", "#", "[", "]", "@", "?", "/"
 - Sub-Delimiters: "!", "$", "&", "'", "(", ")", "*", "+", ",", ";", "="
 
 - parameter string: The string to be percent-escaped.
 - returns: The percent-escaped string.
 */
NSString * AFOAuth1PercentEscapedStringFromString(NSString *string) {
    static NSString * const kAFCharactersGeneralDelimitersToEncode = @":#[]@?/";
    static NSString * const kAFCharactersSubDelimitersToEncode = @"!$&'()*+,;=";
    
    NSMutableCharacterSet * allowedCharacterSet = [[NSCharacterSet URLQueryAllowedCharacterSet] mutableCopy];
    [allowedCharacterSet removeCharactersInString:[kAFCharactersGeneralDelimitersToEncode stringByAppendingString:kAFCharactersSubDelimitersToEncode]];
    
    // FIXME: https://github.com/AFNetworking/AFNetworking/pull/3028
    // return [string stringByAddingPercentEncodingWithAllowedCharacters:allowedCharacterSet];
    
    static NSUInteger const batchSize = 50;
    
    NSUInteger index = 0;
    NSMutableString *escaped = @"".mutableCopy;
    
    while (index < string.length) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wgnu"
        NSUInteger length = MIN(string.length - index, batchSize);
#pragma GCC diagnostic pop
        NSRange range = NSMakeRange(index, length);
        
        // To avoid breaking up character sequences such as 👴🏻👮🏽
        range = [string rangeOfComposedCharacterSequencesForRange:range];
        
        NSString *substring = [string substringWithRange:range];
        NSString *encoded = [substring stringByAddingPercentEncodingWithAllowedCharacters:allowedCharacterSet];
        [escaped appendString:encoded];
        
        index += range.length;
    }
    
    return escaped;
}

NSString * AFOAuth1QueryStringFromParameters(NSDictionary *parameters) {
    NSMutableArray *mutablePairs = [NSMutableArray array];
    for (NSString *key in parameters) {
        NSString *value = parameters[key];
        NSString *pair = [NSString stringWithFormat:@"%@=%@", AFOAuth1PercentEscapedStringFromString(key), AFOAuth1PercentEscapedStringFromString(value)];
        [mutablePairs addObject:pair];
    }
    
    return [mutablePairs componentsJoinedByString:@"&"];
}

NSString * AFOAuth1PlainTextSignature(NSURLRequest *request, NSString *consumerSecret, NSString *tokenSecret, NSStringEncoding stringEncoding) {
    NSString *secret = tokenSecret ? tokenSecret : @"";
    NSString *signature = [NSString stringWithFormat:@"%@&%@", consumerSecret, secret];
    return signature;
}

NSString * AFOAuth1HMACSHA1Signature(NSURLRequest *request, NSString *consumerSecret, NSString *tokenSecret, NSStringEncoding stringEncoding) {
    NSString *secret = tokenSecret ? tokenSecret : @"";
    NSString *secretString = [NSString stringWithFormat:@"%@&%@", AFOAuth1PercentEscapedStringFromString(consumerSecret), AFOAuth1PercentEscapedStringFromString(secret)];
    NSData *secretStringData = [secretString dataUsingEncoding:stringEncoding];
    
    NSString *queryString = AFOAuth1PercentEscapedStringFromString(AFOAuth1SortedQueryString(request.URL.query));
    NSString *urlWithoutQueryString = AFOAuth1PercentEscapedStringFromString([request.URL.absoluteString componentsSeparatedByString:@"?"][0]);
    NSString *requestString = [NSString stringWithFormat:@"%@&%@&%@", request.HTTPMethod, urlWithoutQueryString, queryString];
    NSData *requestStringData = [requestString dataUsingEncoding:stringEncoding];
    
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CCHmacContext cx;
    CCHmacInit(&cx, kCCHmacAlgSHA1, secretStringData.bytes, secretStringData.length);
    CCHmacUpdate(&cx, requestStringData.bytes, requestStringData.length);
    CCHmacFinal(&cx, digest);
    
    return [[NSData dataWithBytes:digest length:CC_SHA1_DIGEST_LENGTH] base64EncodedStringWithOptions:0];
}

NSString * AFOAuth1SortedQueryString(NSString *queryString) {
    return [[[queryString componentsSeparatedByString:@"&"] sortedArrayUsingSelector:@selector(compare:)] componentsJoinedByString:@"&"];
}

NSArray *AFOAuth1SortedQueryItemsFromQueryString(NSString *queryString) {
    NSArray *sortedQueryPairs = [[queryString componentsSeparatedByString:@"&"] sortedArrayUsingSelector:@selector(compare:)];
    NSMutableArray *sortedQueryItems = [[NSMutableArray alloc] init];
    for (NSString *queryPair in sortedQueryPairs) {
        NSArray *queryItem = [queryPair componentsSeparatedByString:@"="];
        [sortedQueryItems addObject:queryItem];
    }
    return sortedQueryItems;
}

NSDictionary * AFOAuth1ParametersFromQueryString(NSString *queryString) {
    NSArray *sortedQueryItems = AFOAuth1SortedQueryItemsFromQueryString(queryString);
    NSMutableDictionary *parameters = [[NSMutableDictionary alloc] init];
    for (NSArray *queryItem in sortedQueryItems) {
        switch (queryItem.count) {
            case 1: {
                NSString *key = queryItem[0];
                parameters[key] = [NSNull null];
            } break;
            case 2: {
                NSString *key = queryItem[0];
                NSString *value = queryItem[1];
                parameters[key] = value;
            } break;
            default: {
                NSLog(@"Ignoring query item:\n%@", queryItem);
            } break;
        }
    }
    return parameters;
}

// FIXME: (me@lxcid.com) No support for nested parameters.
NSArray * AFOAuth1SortedQueryItemsFromParameters(NSDictionary *parameters) {
    NSMutableArray *queryItems = [NSMutableArray array];
    [parameters enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
        [queryItems addObject:@[ key, obj ]];
    }];
    [queryItems sortUsingComparator:^NSComparisonResult(NSArray *queryItem1, NSArray *queryItem2) {
        id key1 = queryItem1.firstObject;
        id key2 = queryItem2.firstObject;
        return [key1 compare:key2];
    }];
    return [queryItems copy];
}

BOOL AFOAuth1IsQueryStringValueTrue(NSString *value) {
    return value && [value.lowercaseString hasPrefix:@"t"];
}
