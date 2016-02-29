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

/**
 Returns a OAuth1 nounce using the UUID.
 
 @return A OAuth nounce.
 */
FOUNDATION_EXPORT NSString * AFOAuth1Nounce();

/**
 Returns a percent-escaped string for a header string key or value.
 RFC 3986 states that the following characters are "reserved" characters.
 - General Delimiters: ":", "#", "[", "]", "@", "?", "/"
 - Sub-Delimiters: "!", "$", "&", "'", "(", ")", "*", "+", ",", ";", "="
 
 @param string The string to be percent-escaped.
 
 @return The percent-escaped string.
 */
FOUNDATION_EXPORT NSString * AFOAuth1PercentEscapedStringFromString(NSString *string);

/**
 Returns a query string for the given parameters.
 
 @param parameters The parameters to serialize.
 
 @return The query string.
 */
FOUNDATION_EXPORT NSString * AFOAuth1QueryStringFromParameters(NSDictionary *parameters);

/**
 Returns parameters of the given query.
 
 @param queryString The query string to deserialize.
 
 @return The parameters.
 */
FOUNDATION_EXPORT NSDictionary * AFOAuth1ParametersFromQueryString(NSString *queryString);

/**
 Returns a PLAINTEXT signature.
 
 @param request        The request to sign.
 @param consumerSecret The consumer secret.
 @param tokenSecret    The token secret.
 @param stringEncoding The string encoding.
 
 @return The request signature.
 */
FOUNDATION_EXPORT NSString * AFOAuth1PlainTextSignature(NSURLRequest *request, NSString *consumerSecret, NSString *tokenSecret, NSStringEncoding stringEncoding);

/**
 Returns an HMAC-SHA1 signature.
 
 @param request        The request to sign.
 @param consumerSecret The consumer secret.
 @param tokenSecret    The token secret.
 @param stringEncoding The string encoding.
 
 @return The request signature.
 */
FOUNDATION_EXPORT NSString * AFOAuth1HMACSHA1Signature(NSURLRequest *request, NSString *consumerSecret, NSString *tokenSecret, NSStringEncoding stringEncoding);

/**
 Returns sorted query string.
 
 @param queryString The query string to sort.
 
 @return The sorted query string.
 */
FOUNDATION_EXPORT NSString * AFOAuth1SortedQueryString(NSString *queryString);

/**
 Returns sorted query items from query string.
 
 @param queryString The query string.
 
 @return The sorted query items.
 */
FOUNDATION_EXPORT NSArray *AFOAuth1SortedQueryItemsFromQueryString(NSString *queryString);

/**
 Returns sorted query items from parameters.
 
 @param parameters The parameters
 
 @return The sorted query items.
 */
FOUNDATION_EXPORT NSArray * AFOAuth1SortedQueryItemsFromParameters(NSDictionary *parameters);

/**
 Returns YES if the value starts with a 't' or 'T'.
 
 @param value The query string value to check.
 
 @return Yes if the value is true.
 */
FOUNDATION_EXPORT BOOL AFOAuth1IsQueryStringValueTrue(NSString *value);
