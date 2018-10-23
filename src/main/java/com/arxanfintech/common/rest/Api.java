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
import java.security.KeyStore;

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

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

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
    
    // 双向认证需要的参数 手动导入证书
    private String keyStorePath = "";
    private String keyStorePasswd = "";
    private String trustStorePath = "";
    private String trustStorePasswd = "";

    /**
     * create https client with root cert and client-key client-cert
     * 
     * @param keyStorePath
     *            keystore of client cert
     * @param keyStorePasswd
     *            password of client keystore
     * @param trustStorePath
     *            keystore of server root cert
     * @param trustStorePasswd
     *            password of trustKeystore
     * @since 3.0  
     */ 
    public Api(String keyStorePath, String keyStorePasswd, String trustStorePath, String trustStorePasswd) throws Exception {
    	this.keyStorePath = keyStorePath;
    	this.keyStorePasswd = keyStorePasswd;
    	this.trustStorePath = trustStorePath;
    	this.trustStorePasswd = trustStorePasswd;
    	
    	httpclient = this.NewHttpsClient();
	}

    // 双向认证需要提供 KeyStore 和 TrustStore
    private CloseableHttpClient NewHttpsClient() throws Exception {
        if (httpclient == null) {
        	// 设置keystory
        	KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType()); // "jks/PKSC12"
        	keyStore.load(new FileInputStream(keyStorePath), keyStorePasswd.toCharArray());
        	KeyManagerFactory keymg = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        	keymg.init(keyStore, keyStorePasswd.toCharArray());
        	
        	// 设置 trust keystory
        	KeyStore trustKeyStore = KeyStore.getInstance(KeyStore.getDefaultType()); // "jks"
        	trustKeyStore.load(new FileInputStream(trustStorePath), trustStorePasswd.toCharArray());
        	TrustManagerFactory trustKeyMg = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); // "SunX509"
        	trustKeyMg.init(trustKeyStore);

        	// SSLContext 要用KeyManagerFactory和TrustManagerFactory对象来初始化
        	SSLContext sslcontext = SSLContext.getInstance("TLS");
        	sslcontext.init(keymg.getKeyManagers(), trustKeyMg.getTrustManagers(), null);
        	
            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext);
            httpclient = HttpClients.custom().setSSLSocketFactory(sslsf).build();
        }
        return httpclient;
    }
    
    /**
     *  create http client
     * 
     */
    public Api() throws Exception {
    	if (this.httpclient == null) {
    		SSLContext sslcontext = SSLContexts.custom().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build();
    		SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext);
    		this.httpclient = HttpClients.custom().setSSLSocketFactory(sslsf).build();
    	}
    }

    public String DoGet(Request request) throws Exception {
        try {
            Unirest.setHttpClient(this.httpclient);

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
