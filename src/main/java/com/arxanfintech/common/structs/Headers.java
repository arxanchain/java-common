/*******************************************************************************
Copyright ArxanFintech Technology Ltd. 2018 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*******************************************************************************/
package com.arxanfintech.common.structs;

public class Headers {
    public static String UserIdHeader = "User-Id";
    public static String UserRoleHeader = "User-Role";
    public static String ChannelIdHeader = "Channel-Id";
    public static String ChaincodeIdHeader = "Chaincode-Id";
    public static String XAuthTokenHeader = "X-Auth-Token";
    public static String XSubjectTokenHeader = "X-Subject-Token";
    public static String ACLActionHeader = "ACL-Action";
    public static String APIKeyHeader = "API-Key";
    public static String EnrollmentIdHeader = "Enrollment-Id";
    public static String CryptoModeHeader = "Crypto-Mode";
    public static String AuthModeHeader = "Auth-Mode";

    // defined a new auth mode to auth channel/chaincode, for we need auth token and
    // channel/chaincode
    public static String AuthChannelModeHeader = "Auth-ChCC-Mode";

    // defined a new auth mode to auth SN
    public static String AuthSNModeHeader = "Auth-SN-Mode";
    public static String AuthEmailHeader = "Auth-Email";
    public static String FileAuthTokenHeader = "Auth-Token";
    public static String FabioRouteTagHeader = "Host";
    public static String CallbackUrlHeader = "Callback-Url";
    public static String RouteTagHeader = "Route-Tag";
    public static String InvokeModeHeader = "Bc-Invoke-Mode";
}