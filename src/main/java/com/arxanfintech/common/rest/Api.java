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

package com.arxanfintech.common.rest;

import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.arxanfintech.common.structs.Headers;
import com.arxanfintech.common.util.Utils;

import java.util.Map;

import javax.net.ssl.SSLContext;

import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.ssl.SSLContexts;

/**
 * 
 * Rest api Rest api for java common
 *
 */
public class Api {

    public CloseableHttpClient httpclient;

    public CloseableHttpClient NewHttpClient() throws Exception {
        if (httpclient == null) {
            SSLContext sslcontext = SSLContexts.custom().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build();

            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext);
            CloseableHttpClient httpclient = HttpClients.custom().setSSLSocketFactory(sslsf).build();
        }
        return httpclient;
    }

    /**
     * httpclient get
     *
     * @param request
     *            http get info
     * @return response data
     */
    public String DoGet(Request request) throws Exception {

        SSLContext sslcontext = SSLContexts.custom().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build();

        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext);
        CloseableHttpClient httpclient = HttpClients.custom().setSSLSocketFactory(sslsf).build();
        Unirest.setHttpClient(httpclient);

        if (request.client == null) {
            throw new Exception("client must NOT null");
        }

        Map<String, String> mapHeader = Utils.JsonToMap(request.header);
        mapHeader.put(Headers.APIKeyHeader, request.client.GetApiKey());

        if (request.client.GetRouteTag() != "") {
            mapHeader.put(Headers.FabioRouteTagHeader, request.client.GetRouteTag());
            mapHeader.put(Headers.RouteTagHeader, request.client.GetRouteTag());
        }

        HttpResponse<String> res = Unirest.get(request.url).headers(mapHeader).asString();
        String respData = res.getBody();
        System.out.println("Got remote cipher response: " + respData);

        String oriData = "";
        if (request.client.GetEnableCrypto()) {
            oriData = request.crypto.decryptAndVerify(respData.getBytes());
        } else {
            oriData = respData;
        }

        return oriData;
    }

    /**
     * httpclient post
     *
     * @param request
     *            http post info
     * @return response data
     */
    public String DoPost(Request request) throws Exception {

        SSLContext sslcontext = SSLContexts.custom().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build();

        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext);
        CloseableHttpClient httpclient = HttpClients.custom().setSSLSocketFactory(sslsf).build();
        Unirest.setHttpClient(httpclient);

        if (request.client == null) {
            throw new Exception("client must NOT null");
        }

        String buf = "";
        if (request.client.GetEnableCrypto()) {
            buf = request.crypto.signAndEncrypt(request.body.toString().getBytes());
        } else {
            buf = request.body.toString();
        }

        Map<String, String> mapHeader = Utils.JsonToMap(request.header);
        mapHeader.put(Headers.APIKeyHeader, request.client.GetApiKey());

        if (request.client.GetRouteTag() != "") {
            mapHeader.put(Headers.FabioRouteTagHeader, request.client.GetRouteTag());
            mapHeader.put(Headers.RouteTagHeader, request.client.GetRouteTag());
        }

        System.out.println("after sign and encrypt : " + buf);
        HttpResponse<String> res = Unirest.post(request.url).headers(mapHeader).body(buf).asString();

        String respData = res.getBody();

        System.out.println("Got remote cipher response: " + respData);

        String oriData = "";
        if (request.client.GetEnableCrypto()) {
            oriData = request.crypto.decryptAndVerify(respData.getBytes());
        } else {
            oriData = respData;
        }

        return oriData;

    }

    /**
     * httpclient put
     *
     * @param request
     *            http post info
     * @return response data
     */
    public String DoPut(Request request) throws Exception {

        SSLContext sslcontext = SSLContexts.custom().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build();

        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext);
        CloseableHttpClient httpclient = HttpClients.custom().setSSLSocketFactory(sslsf).build();
        Unirest.setHttpClient(httpclient);

        if (request.client == null) {
            throw new Exception("client must NOT null");
        }

        String buf = "";
        if (request.client.GetEnableCrypto()) {
            buf = request.crypto.signAndEncrypt(request.body.toString().getBytes());
        } else {
            buf = request.body.toString();
        }

        Map<String, String> mapHeader = Utils.JsonToMap(request.header);
        mapHeader.put(Headers.APIKeyHeader, request.client.GetApiKey());

        if (request.client.GetRouteTag() != "") {
            mapHeader.put(Headers.FabioRouteTagHeader, request.client.GetRouteTag());
            mapHeader.put(Headers.RouteTagHeader, request.client.GetRouteTag());
        }

        HttpResponse<String> res = Unirest.put(request.url).headers(mapHeader).body(buf).asString();

        String respData = res.getBody();

        System.out.println("Got remote cipher response: " + respData);

        String oriData = "";
        if (request.client.GetEnableCrypto()) {
            oriData = request.crypto.decryptAndVerify(respData.getBytes());
        } else {
            oriData = respData;
        }
        return oriData;

    }
}
