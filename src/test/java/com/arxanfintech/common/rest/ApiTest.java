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

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import com.arxanfintech.common.rest.Api;
import com.arxanfintech.common.rest.Request;
import org.apache.http.message.BasicNameValuePair;

/**
 * Unit test for RestApi
 */
public class ApiTest extends TestCase {
    /**
     * Create the test case
     *
     * @param testName
     *            name of the test case
     */
    public ApiTest(String testName) {
        super(testName);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite() {
        return new TestSuite(ApiTest.class);
    }

    /**
     * Rigourous testGet :-)
     */
    public void testGet() {
        Api api = new Api();
        api.NewHttpClient();
        Request get = new Request();
        get.url = "http://httpbin.org/get";
        try {
            api.DoGet(get);
            assertTrue(true);
        } catch (Exception e) {
            assertTrue(false);
        }
    }

    /**
     * Rigourous testPost :-)
     */
    public void testPost() {
        Api api = new Api();
        api.NewHttpClient();
        Request post = new Request();
        post.url = "http://httpbin.org/post";
        post.body.add(new BasicNameValuePair("username", "vip"));
        post.body.add(new BasicNameValuePair("password", "secret"));
        try {
            api.DoPost(post);
            assertTrue(true);
        } catch (Exception e) {
            assertTrue(false);
        }

    }
}
