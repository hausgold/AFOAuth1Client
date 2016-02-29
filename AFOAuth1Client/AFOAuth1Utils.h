// AFOAuth1Utils.h
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

#import <Foundation/Foundation.h>

FOUNDATION_EXPORT NSString * AFOAuth1Nounce();

FOUNDATION_EXPORT NSString * AFOAuth1PlainTextSignature(NSURLRequest *request, NSString *consumerSecret, NSString *tokenSecret, NSStringEncoding stringEncoding);

/**
 Returns a percent-escaped string for a header string key or value.
 RFC 3986 states that the following characters are "reserved" characters.
 - General Delimiters: ":", "#", "[", "]", "@", "?", "/"
 - Sub-Delimiters: "!", "$", "&", "'", "(", ")", "*", "+", ",", ";", "="
 
 - parameter string: The string to be percent-escaped.
 - returns: The percent-escaped string.
 */
FOUNDATION_EXPORT NSString * AFOAuth1PercentEscapedStringFromString(NSString *string);

FOUNDATION_EXPORT NSString * AFOAuth1QueryStringFromParameters(NSDictionary *parameters);

FOUNDATION_EXPORT NSString * AFOAuth1HMACSHA1Signature(NSURLRequest *request, NSString *consumerSecret, NSString *tokenSecret, NSStringEncoding stringEncoding);

FOUNDATION_EXPORT NSDictionary * AFOAuth1ParametersFromQueryString(NSString *queryString);

FOUNDATION_EXPORT NSString * AFOAuth1SortedQueryString(NSString *queryString);

FOUNDATION_EXPORT NSArray *AFOAuth1SortedQueryItemsFromQueryString(NSString *queryString);

FOUNDATION_EXPORT NSArray * AFOAuth1SortedQueryItemsFromParameters(NSDictionary *parameters);

FOUNDATION_EXPORT BOOL AFOAuth1IsQueryStringValueTrue(NSString *value);
