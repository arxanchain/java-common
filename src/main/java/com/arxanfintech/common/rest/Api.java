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

import java.util.ArrayList;
import java.util.List;

import javax.xml.ws.spi.http.HttpHandler;

import org.apache.http.Header;
import org.apache.http.HeaderElement;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.NameValuePair;
import org.apache.http.ParseException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import java.io.File;
import java.io.FileInputStream;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.arxanfintech.common.crypto.Crypto;
import com.arxanfintech.common.structs.Headers;
import com.arxanfintech.common.util.Utils;

import java.io.FileInputStream;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.SSLContext;

import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.alibaba.fastjson.JSON;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;

import com.alibaba.fastjson.JSONObject;

import com.arxanfintech.common.crypto.Crypto;

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

    public String DoGet(Request request) throws Exception {
        try {
            SSLContext sslcontext = SSLContexts.custom().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build();

            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext);
            CloseableHttpClient httpclient = HttpClients.custom().setSSLSocketFactory(sslsf).build();
            Unirest.setHttpClient(httpclient);

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
        } catch (Exception e) {
            System.out.println(e.getMessage());

        }
        return null;
    }

    /**
     * httpclient post
     *
     * @param request
     *            http post info
     * @return response data error return null
     */
    public String DoPost(Request request) {
        try {
            SSLContext sslcontext = SSLContexts.custom().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build();

            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext);
            CloseableHttpClient httpclient = HttpClients.custom().setSSLSocketFactory(sslsf).build();
            Unirest.setHttpClient(httpclient);

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
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return "";
    }

    /**
     * httpclient put
     *
     * @param request
     *            http post info
     * @return response data error return null
     */
    public String DoPut(Request request) {
        try {
            SSLContext sslcontext = SSLContexts.custom().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build();

            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext);
            CloseableHttpClient httpclient = HttpClients.custom().setSSLSocketFactory(sslsf).build();
            Unirest.setHttpClient(httpclient);

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
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return "";
    }

    /**
     * httpclient post file
     *
     * @param request
     *            http post info
     * @return response data error return null
     */
    public String DoUploadFile(Request request, String filename, String poeid, Boolean readonly) {
        try {
            SSLContext sslcontext = SSLContexts.custom().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build();

            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext);
            CloseableHttpClient httpclient = HttpClients.custom().setSSLSocketFactory(sslsf).build();
            Unirest.setHttpClient(httpclient);

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

            HttpResponse<String> res = Unirest.post(request.url).headers(mapHeader).field("poe_id", poeid)
                    .field("read_only", readonly).field("poe_file", filename).field("file", new File(filename))
                    .asString();

            // final InputStream stream = new FileInputStream(new
            // File(getClass().getResource(filename).toURI()));
            // final byte[] bytes = new byte[stream.available()];
            // stream.read(bytes);
            // stream.close();
            // .field("file", bytes, filename)

            // .field("file", new FileInputStream(new
            // File(getClass().getResource(filename).toURI())),
            // ContentType.APPLICATION_OCTET_STREAM, filename)

            String respData = res.getBody();

            System.out.println("Got remote cipher response: " + respData);

            String oriData = "";
            if (request.client.GetEnableCrypto()) {
                oriData = request.crypto.decryptAndVerify(respData.getBytes());
            } else {
                oriData = respData;
            }

            return oriData;
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return "";
    }
}
