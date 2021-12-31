## Envoy WASM and LUA filters for Certificate Bound Tokens

Envoy LUA and wasm filters that enforce very basic [Certificate Bound Tokens](https://connect2id.com/learn/token-binding).

The basic idea behind bound tokens is that the signed bearer token itself has information embedded within it which defines the transport/TLS client certificate that is presented.

That is, information provided within a presented client cert during mTLS with a resource server will be used to cross validate the bearer token which was encoded and bound to that certificate.

Binding the token to the cert reduces the security risk of bearer tokens which as the name suggests can be used by arbitrary callers.  With bound tokens, the call must also demonstrate that they are in possession of the client certificate.

In the easiest flow, the bearer token that is ultimately used against a resource gets minted by a service which will verify that the client is infact in possession of certificate.  One way to do that is to use the same mTLS certs to interact with the Authorization server that will eventually get used on the Resource Server.  The more complicated flows involve multiple certificates but those flows are not described here.

>> `12/1/20`: NOTE:  the wasm plugin is not yet ready.  It is pending implementation of [envoy issue#14229](https://github.com/envoyproxy/envoy/issues/14229).  However, i do describe how to build the plugin anyway.
>> `12/29/21`: the wasm plugin is still not ready since envoy wasm doesn't surface the cert signature.  However, i was able to modify envoy to emit those values and actually process them in the sample wasm binary below

---

### Background

`OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens` [rfc 8705](https://tools.ietf.org/html/rfc8705) describes a mechanism where a specific specific claim in a JWT bearer token presented to a server includes the hash of the public certificate that is authorized and corresponds to the mTLS certificate currently used during the connection.

For example, if the public cert used by the client is `clientjwt.crt`, then the thumbprint is calculate as such and gets included into the JWT by the token issuer

```
3.1.  JWT Certificate Thumbprint Confirmation Method

   When access tokens are represented as JSON Web Tokens (JWT)[RFC7519],
   the certificate hash information SHOULD be represented using the
   "x5t#S256" confirmation method member defined herein.

   To represent the hash of a certificate in a JWT, this specification
   defines the new JWT Confirmation Method [RFC7800] member "x5t#S256"
   for the X.509 Certificate SHA-256 Thumbprint.  The value of the
   "x5t#S256" member is a base64url-encoded [RFC4648] SHA-256 [SHS] hash
   (a.k.a. thumbprint, fingerprint or digest) of the DER encoding [X690]
   of the X.509 certificate [RFC5280].  The base64url-encoded value MUST
   omit all trailing pad '=' characters and MUST NOT include any line
   breaks, whitespace, or other additional characters.
```

```bash
$ openssl x509 -in clientjwt.crt -outform DER | openssl dgst -sha256 | cut -d" " -f2
915fc54c3fc19651ca22600c96aa9b126e8ba073b44185804cee5ff36dd87240

$ echo "915fc54c3fc19651ca22600c96aa9b126e8ba073b44185804cee5ff36dd87240" | xxd -r -p - | openssl enc -a | tr -d '=' | tr '/+' '_-'
kV_FTD_BllHKImAMlqqbEm6LoHO0QYWATO5f823YckA
```

Which eventually is sealed into a bearer token (JWT in this case) using the following claim:

```json
{
  "cbf": {
    "x5t#S256": "kV_FTD_BllHKImAMlqqbEm6LoHO0QYWATO5f823YckA"
  }
}
```

The resource server is expected to verify the mTLS connections' client public key against this value.


### Bind certificate hash to bearer token

The golang application provided here will generate the `x5t` hash value and then encode it into a JWT token.  This token can then be used to contact the resource server

```bash
cd jwt_token/

$ go run main.go --capubFile ../certs/tls-ca.crt  \
   --caprivFile ../certs/tls-ca.key   --clientpubCert ../certs/clientjwt.crt 

eyJhbGciOiJSUzI1NiIsImtpZCI6IjIiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2Zvby5iYXIiLCJleHAiOjE2NzE2ODE0MjgsImlhdCI6MTY0MDkyMzAyOCwiaXNzIjoiaHR0cHM6Ly9teWlzc3VlciIsImNiZiI6eyJ4NXQjUzI1NiI6ImtWX0ZURF9CbGxIS0ltQU1scXFiRW02TG9ITzBRWVdBVE81ZjgyM1lja0EifX0.JpHhIf5rd0Pn1r__RdquhZDzsejJICJojR4YEA0Nux9Y3gXHb4WryrerZTu97qnzVKhZlw1KpVvLXjdBFYJLTDQy896n58m7CRp147T-3jgc4-WiRbj7bwDNGtQCO9_OHZkmquDp2NZUI5UqDWa4QbwSjby5HbCtnMOKtHbPGLd8YQ_PJRoixokC4i34E_otgNQ7BwNTzDU1-sl7LWJTrgJDkJ5OFMPm_x7wrcd6VQ_hQ0dQD3oaqXD_97--SKhNcIySdf8DkdE9rIdZtXtS6aHsAXiH9YDPXLRF4Br93w5QQw9E433Rt2Ov_tAg0t_NbTlMjf5r3Vzg3byHNdoeGg
```

will give a token like

```json
{
  "alg": "RS256",
  "kid": "2",
  "typ": "JWT"
}
{
  "aud": "https://foo.bar",
  "exp": 1671681428,
  "iat": 1640923028,
  "iss": "https://myissuer",
  "cbf": {
    "x5t#S256": "kV_FTD_BllHKImAMlqqbEm6LoHO0QYWATO5f823YckA"
  }
}
```

export the value

```bash
export TOKEN=eyJhbGciOiJSUzI1NiIsImtpZCI6IjIiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2Zvby5iYXIiLCJleHAiOjE2NzE2ODE0MjgsImlhdCI6MTY0MDkyMzAyOCwiaXNzIjoiaHR0cHM6Ly9teWlzc3VlciIsImNiZiI6eyJ4NXQjUzI1NiI6ImtWX0ZURF9CbGxIS0ltQU1scXFiRW02TG9ITzBRWVdBVE81ZjgyM1lja0EifX0.JpHhIf5rd0Pn1r__RdquhZDzsejJICJojR4YEA0Nux9Y3gXHb4WryrerZTu97qnzVKhZlw1KpVvLXjdBFYJLTDQy896n58m7CRp147T-3jgc4-WiRbj7bwDNGtQCO9_OHZkmquDp2NZUI5UqDWa4QbwSjby5HbCtnMOKtHbPGLd8YQ_PJRoixokC4i34E_otgNQ7BwNTzDU1-sl7LWJTrgJDkJ5OFMPm_x7wrcd6VQ_hQ0dQD3oaqXD_97--SKhNcIySdf8DkdE9rIdZtXtS6aHsAXiH9YDPXLRF4Br93w5QQw9E433Rt2Ov_tAg0t_NbTlMjf5r3Vzg3byHNdoeGg
```

## Get Envoy

Finally, get a copy of envoy that supports `wasm`

>> **NOTE**:  we are using `envoy 1.17`

```bash
docker cp `docker create envoyproxy/envoy-dev:latest`:/usr/local/bin/envoy /tmp/

/tmp/envoy --version
   version: 483dd3007f15e47deed0a29d945ff776abb37815/1.17.0-dev/Clean/RELEASE/BoringSSL
```

## Deploy

We are now ready to startup envoy and give it all a go.  You can try either wasm (eventually) or lua 

Note, i've described how to build wasm below but thats just a placeholder until the feature with envoy described above is implemented.

### LUA

To test with `LUA`, simply run

```bash
/tmp/envoy -c lua.yaml -l debug
```

## CURL

Invoke the endpoint

```bash
echo $TOKEN
curl -v -H "Authorization: Bearer $TOKEN" \
  -H "host: http.domain.com" \
  --resolve  http.domain.com:8080:127.0.0.1 \
  --cert certs/clientjwt.crt \
  --key certs/clientjwt.key  \
  --cacert certs/tls-ca.crt   https://http.domain.com:8080/get
```

In the envoy logs, you should see the jwt claims extracted and then validated:

```log
[2021-12-30 23:04:44.961][3253540][debug][http] [source/common/http/conn_manager_impl.cc:274] [C0] new stream
[2021-12-30 23:04:44.961][3253540][debug][http] [source/common/http/conn_manager_impl.cc:867] [C0][S63392630867835062] request headers complete (end_stream=true):
':authority', 'http.domain.com'
':path', '/get'
':method', 'GET'
'user-agent', 'curl/7.79.1'
'accept', '*/*'
'authorization', 'Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjIiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2Zvby5iYXIiLCJleHAiOjE2NzE2ODE0MjgsImlhdCI6MTY0MDkyMzAyOCwiaXNzIjoiaHR0cHM6Ly9teWlzc3VlciIsImNiZiI6eyJ4NXQjUzI1NiI6ImtWX0ZURF9CbGxIS0ltQU1scXFiRW02TG9ITzBRWVdBVE81ZjgyM1lja0EifX0.JpHhIf5rd0Pn1r__RdquhZDzsejJICJojR4YEA0Nux9Y3gXHb4WryrerZTu97qnzVKhZlw1KpVvLXjdBFYJLTDQy896n58m7CRp147T-3jgc4-WiRbj7bwDNGtQCO9_OHZkmquDp2NZUI5UqDWa4QbwSjby5HbCtnMOKtHbPGLd8YQ_PJRoixokC4i34E_otgNQ7BwNTzDU1-sl7LWJTrgJDkJ5OFMPm_x7wrcd6VQ_hQ0dQD3oaqXD_97--SKhNcIySdf8DkdE9rIdZtXtS6aHsAXiH9YDPXLRF4Br93w5QQw9E433Rt2Ov_tAg0t_NbTlMjf5r3Vzg3byHNdoeGg'

[2021-12-30 23:04:44.961][3253540][debug][http] [source/common/http/filter_manager.cc:835] [C0][S63392630867835062] request end stream
[2021-12-30 23:04:44.961][3253540][debug][jwt] [source/extensions/filters/http/jwt_authn/filter.cc:158] Called Filter : setDecoderFilterCallbacks
[2021-12-30 23:04:44.961][3253540][debug][jwt] [source/extensions/filters/http/jwt_authn/filter.cc:53] Called Filter : decodeHeaders
[2021-12-30 23:04:44.961][3253540][debug][jwt] [source/extensions/filters/http/jwt_authn/matcher.cc:70] Prefix requirement '/' matched.
[2021-12-30 23:04:44.961][3253540][debug][jwt] [source/extensions/filters/http/jwt_authn/extractor.cc:249] extract authorizationBearer 
[2021-12-30 23:04:44.961][3253540][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:133] custom-jwt: JWT authentication starts (allow_failed=false), tokens size=1
[2021-12-30 23:04:44.961][3253540][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:144] custom-jwt: startVerify: tokens size 1
[2021-12-30 23:04:44.961][3253540][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:157] custom-jwt: Parse Jwt eyJhbGciOiJSUzI1NiIsImtpZCI6IjIiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2Zvby5iYXIiLCJleHAiOjE2NzE2ODE0MjgsImlhdCI6MTY0MDkyMzAyOCwiaXNzIjoiaHR0cHM6Ly9teWlzc3VlciIsImNiZiI6eyJ4NXQjUzI1NiI6ImtWX0ZURF9CbGxIS0ltQU1scXFiRW02TG9ITzBRWVdBVE81ZjgyM1lja0EifX0.JpHhIf5rd0Pn1r__RdquhZDzsejJICJojR4YEA0Nux9Y3gXHb4WryrerZTu97qnzVKhZlw1KpVvLXjdBFYJLTDQy896n58m7CRp147T-3jgc4-WiRbj7bwDNGtQCO9_OHZkmquDp2NZUI5UqDWa4QbwSjby5HbCtnMOKtHbPGLd8YQ_PJRoixokC4i34E_otgNQ7BwNTzDU1-sl7LWJTrgJDkJ5OFMPm_x7wrcd6VQ_hQ0dQD3oaqXD_97--SKhNcIySdf8DkdE9rIdZtXtS6aHsAXiH9YDPXLRF4Br93w5QQw9E433Rt2Ov_tAg0t_NbTlMjf5r3Vzg3byHNdoeGg
[2021-12-30 23:04:44.961][3253540][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:167] custom-jwt: Verifying JWT token of issuer https://myissuer
[2021-12-30 23:04:44.961][3253540][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:315] custom-jwt: JWT token verification completed with: OK
[2021-12-30 23:04:44.961][3253540][debug][jwt] [source/extensions/filters/http/jwt_authn/filter.cc:110] Jwt authentication completed with: OK

[2021-12-30 23:04:44.962][3253540][info][lua] [source/extensions/filters/http/lua/lua_filter.cc:795] script log: Peer Signature: kV_FTD_BllHKImAMlqqbEm6LoHO0QYWATO5f823YckA

[2021-12-30 23:04:44.962][3253540][info][lua] [source/extensions/filters/http/lua/lua_filter.cc:795] script log: JWT Signature: kV_FTD_BllHKImAMlqqbEm6LoHO0QYWATO5f823YckA

[2021-12-30 23:04:44.962][3253540][debug][lua] [source/extensions/filters/common/lua/lua.cc:39] coroutine finished
[2021-12-30 23:04:44.962][3253540][debug][router] [source/common/router/router.cc:457] [C0][S63392630867835062] cluster 'service_httpbin' match for URL '/get'
[2021-12-30 23:04:44.962][3253540][debug][router] [source/common/router/router.cc:673] [C0][S63392630867835062] router decoding headers:
':authority', 'http.domain.com'
':path', '/get'
':method', 'GET'
':scheme', 'https'
'user-agent', 'curl/7.79.1'
'accept', '*/*'
'x-forwarded-proto', 'https'
'x-request-id', '295b1fc3-1c47-4375-93cf-54deb356cf8c'
'x-envoy-expected-rq-timeout-ms', '15000'

[2021-12-30 23:04:44.962][3253540][debug][pool] [source/common/http/conn_pool_base.cc:74] queueing stream due to no available connections
[2021-12-30 23:04:44.962][3253540][debug][pool] [source/common/conn_pool/conn_pool_base.cc:255] trying to create new connection
[2021-12-30 23:04:44.962][3253540][debug][pool] [source/common/conn_pool/conn_pool_base.cc:143] creating a new connection
[2021-12-30 23:04:44.962][3253540][debug][client] [source/common/http/codec_client.cc:60] [C1] connecting
[2021-12-30 23:04:44.962][3253540][debug][connection] [source/common/network/connection_impl.cc:890] [C1] connecting to 3.223.33.229:80
[2021-12-30 23:04:44.962][3253540][debug][connection] [source/common/network/connection_impl.cc:909] [C1] connection in progress
[2021-12-30 23:04:44.969][3253540][debug][connection] [source/common/network/connection_impl.cc:672] [C1] connected
[2021-12-30 23:04:44.970][3253540][debug][client] [source/common/http/codec_client.cc:88] [C1] connected
[2021-12-30 23:04:44.970][3253540][debug][pool] [source/common/conn_pool/conn_pool_base.cc:293] [C1] attaching to next stream
[2021-12-30 23:04:44.970][3253540][debug][pool] [source/common/conn_pool/conn_pool_base.cc:176] [C1] creating stream
[2021-12-30 23:04:44.970][3253540][debug][router] [source/common/router/upstream_request.cc:416] [C0][S63392630867835062] pool ready
[2021-12-30 23:04:44.979][3253540][debug][router] [source/common/router/router.cc:1285] [C0][S63392630867835062] upstream headers complete: end_stream=false
[2021-12-30 23:04:44.979][3253540][debug][http] [source/common/http/conn_manager_impl.cc:1467] [C0][S63392630867835062] encoding headers via codec (end_stream=false):
':status', '200'
'date', 'Fri, 31 Dec 2021 04:04:44 GMT'
'content-type', 'application/json'
'content-length', '309'
'server', 'envoy'
'access-control-allow-origin', '*'
'access-control-allow-credentials', 'true'
'x-envoy-upstream-service-time', '17'

[2021-12-30 23:04:44.979][3253540][debug][client] [source/common/http/codec_client.cc:132] [C1] response complete
```

### WASM

>> 12/1/20:  wasm based tokenbinding is not yet implemented and is pending [https://github.com/envoyproxy/envoy/issues/14229](https://github.com/envoyproxy/envoy/issues/14229). 

However, I was able to modify envoy to emit those values and see the inside a wasm i just compiled.


#### Upstream Envoy Changes

(as of `12/30/21`)

You can either make the changes below or download the envoy i compiled alredy from the 'release' page on this git repo [here](https://storage.googleapis.com/pki.esodemoapp2.com/envoy_with_tokenbinding_wasm)


The modifiecations to upstream were simple  (from commit `96701cb24611b0f3aac1cc0dd8bf8589fbdf8e9e`).

```text
# git diff
diff --git a/source/extensions/filters/common/expr/context.cc b/source/extensions/filters/common/expr/context.cc
index ac0a47bd9..db801af4f 100644
--- a/source/extensions/filters/common/expr/context.cc
+++ b/source/extensions/filters/common/expr/context.cc
@@ -63,6 +63,10 @@ absl::optional<CelValue> extractSslInfo(const Ssl::ConnectionInfo& ssl_info,
     if (!ssl_info.dnsSansPeerCertificate().empty()) {
       return CelValue::CreateString(&ssl_info.dnsSansPeerCertificate()[0]);
     }
+  } else if (value == SHA256PeerCertificateDigest) {
+    if (!ssl_info.sha256PeerCertificateDigest().empty()) {
+      return CelValue::CreateString(&ssl_info.sha256PeerCertificateDigest());
+    }
   }
   return {};
 }
diff --git a/source/extensions/filters/common/expr/context.h b/source/extensions/filters/common/expr/context.h
index 2f3f2539c..8107d1347 100644
--- a/source/extensions/filters/common/expr/context.h
+++ b/source/extensions/filters/common/expr/context.h
@@ -63,6 +63,7 @@ constexpr absl::string_view URISanLocalCertificate = "uri_san_local_certificate"
 constexpr absl::string_view URISanPeerCertificate = "uri_san_peer_certificate";
 constexpr absl::string_view DNSSanLocalCertificate = "dns_san_local_certificate";
 constexpr absl::string_view DNSSanPeerCertificate = "dns_san_peer_certificate";
+constexpr absl::string_view SHA256PeerCertificateDigest = "sha256_peer_certificate_digest";
 
 // Source properties
 constexpr absl::string_view Source = "source";
```

For me, this what i did

```bash
 git clone https://github.com/envoyproxy/envoy.git
 cd envoy
 git checkout tags/v1.20.1

# make the diff/edits to the two files as shown above
# compile
./ci/run_envoy_docker.sh './ci/do_ci.sh bazel.release.server_only'

# this will take sometime but the brand new envoy will be at
#  /tmp/envoy-docker-build/envoy/source/exe/envoy/envoy

# copy that to your laptop to /tmp/envoy_tbf
# sha256sum /tmp/envoy-docker-build/envoy/source/exe/envoy/envoy
#     975f412ff2381dfb5f2ef5199a21b0715ae4cf8f775cf6bdce8b2a0ab5140565  /tmp/envoy-docker-build/envoy/source/exe/envoy/envoy
```

#### Build WASM

You can either use the wasm binary thats part of this repo or build your own:

to build your own,

```bash
 git clone https://github.com/envoyproxy/envoy.git
 rm -rf envoy/examples/wasm-cc/
 cp -R wasm-cc  envoy/examples/
 cd envoy
 git checkout tags/v1.20.1

bazel build //examples/wasm-cc:envoy_filter_http_wasm_tokenbinding.wasm
```

The newly built envoy binary should be at: `envoy/bazel-bin/examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.wasm`

Now, 

`wasm.yaml` specifies the wasm binary directly from this repo.

```yaml
                  vm_config:
                    runtime: "envoy.wasm.runtime.v8"
                    vm_id: "tb_root_id"
                    code:
                      local:
                        filename: "wasm-binary/envoy_filter_http_wasm_tokenbinding.wasm"    
```

If you compiled your own, modify the path to your own wasm

Finally run the *modified* envoy binary (which you can download from this repo to `/tmp/envoy_with_tokenbinding_wasm`)
```
/tmp/envoy_with_tokenbinding_wasm -c wasm.yaml -l debug
```

(note, i've uploaded the binary to this page [here](https://storage.googleapis.com/pki.esodemoapp2.com/envoy_with_tokenbinding_wasm))

If you send in a curl request like the one above from LUA, you will see, you'll see the certificate fingerprints were extracted from the JWT and TLS session and compared.

```log
[2021-12-30 23:12:21.756][3269492][debug][wasm] [source/extensions/common/wasm/context.cc:1164] 
   wasm log my_plugin tb_root_id tb_root_id: 
   [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:96]::onRequestHeaders() 
   x5t#S256 -> kV_FTD_BllHKImAMlqqbEm6LoHO0QYWATO5f823YckA


[2021-12-30 23:12:21.756][3269492][debug][wasm] [source/extensions/common/wasm/context.cc:1164] 
   wasm log my_plugin tb_root_id tb_root_id: 
   [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:114]::onRequestHeaders() 
   sha256_peer_certificate_digest: kV_FTD_BllHKImAMlqqbEm6LoHO0QYWATO5f823YckA

[2021-12-30 23:12:21.756][3269492][debug][wasm] [source/extensions/common/wasm/context.cc:1164] 
   wasm log my_plugin tb_root_id tb_root_id: 
   [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:121]::onRequestHeaders() 
   sha256_peer_certificate_digest and digest_from_cbf_header matched
```

The full wasm log

```log
[2021-12-30 23:12:21.754][3269492][debug][http] [source/common/http/conn_manager_impl.cc:274] [C0] new stream
[2021-12-30 23:12:21.755][3269492][debug][http] [source/common/http/conn_manager_impl.cc:867] [C0][S13779638144948351405] request headers complete (end_stream=true):
':authority', 'http.domain.com'
':path', '/get'
':method', 'GET'
'user-agent', 'curl/7.79.1'
'accept', '*/*'
'authorization', 'Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjIiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2Zvby5iYXIiLCJleHAiOjE2NzE2ODE0MjgsImlhdCI6MTY0MDkyMzAyOCwiaXNzIjoiaHR0cHM6Ly9teWlzc3VlciIsImNiZiI6eyJ4NXQjUzI1NiI6ImtWX0ZURF9CbGxIS0ltQU1scXFiRW02TG9ITzBRWVdBVE81ZjgyM1lja0EifX0.JpHhIf5rd0Pn1r__RdquhZDzsejJICJojR4YEA0Nux9Y3gXHb4WryrerZTu97qnzVKhZlw1KpVvLXjdBFYJLTDQy896n58m7CRp147T-3jgc4-WiRbj7bwDNGtQCO9_OHZkmquDp2NZUI5UqDWa4QbwSjby5HbCtnMOKtHbPGLd8YQ_PJRoixokC4i34E_otgNQ7BwNTzDU1-sl7LWJTrgJDkJ5OFMPm_x7wrcd6VQ_hQ0dQD3oaqXD_97--SKhNcIySdf8DkdE9rIdZtXtS6aHsAXiH9YDPXLRF4Br93w5QQw9E433Rt2Ov_tAg0t_NbTlMjf5r3Vzg3byHNdoeGg'

[2021-12-30 23:12:21.755][3269492][debug][http] [source/common/http/filter_manager.cc:835] [C0][S13779638144948351405] request end stream
[2021-12-30 23:12:21.755][3269492][debug][jwt] [source/extensions/filters/http/jwt_authn/filter.cc:158] Called Filter : setDecoderFilterCallbacks
[2021-12-30 23:12:21.755][3269492][debug][jwt] [source/extensions/filters/http/jwt_authn/filter.cc:53] Called Filter : decodeHeaders
[2021-12-30 23:12:21.755][3269492][debug][jwt] [source/extensions/filters/http/jwt_authn/matcher.cc:70] Prefix requirement '/' matched.
[2021-12-30 23:12:21.755][3269492][debug][jwt] [source/extensions/filters/http/jwt_authn/extractor.cc:249] extract authorizationBearer 
[2021-12-30 23:12:21.755][3269492][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:133] custom-jwt: JWT authentication starts (allow_failed=false), tokens size=1
[2021-12-30 23:12:21.755][3269492][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:144] custom-jwt: startVerify: tokens size 1
[2021-12-30 23:12:21.755][3269492][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:157] custom-jwt: Parse Jwt eyJhbGciOiJSUzI1NiIsImtpZCI6IjIiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2Zvby5iYXIiLCJleHAiOjE2NzE2ODE0MjgsImlhdCI6MTY0MDkyMzAyOCwiaXNzIjoiaHR0cHM6Ly9teWlzc3VlciIsImNiZiI6eyJ4NXQjUzI1NiI6ImtWX0ZURF9CbGxIS0ltQU1scXFiRW02TG9ITzBRWVdBVE81ZjgyM1lja0EifX0.JpHhIf5rd0Pn1r__RdquhZDzsejJICJojR4YEA0Nux9Y3gXHb4WryrerZTu97qnzVKhZlw1KpVvLXjdBFYJLTDQy896n58m7CRp147T-3jgc4-WiRbj7bwDNGtQCO9_OHZkmquDp2NZUI5UqDWa4QbwSjby5HbCtnMOKtHbPGLd8YQ_PJRoixokC4i34E_otgNQ7BwNTzDU1-sl7LWJTrgJDkJ5OFMPm_x7wrcd6VQ_hQ0dQD3oaqXD_97--SKhNcIySdf8DkdE9rIdZtXtS6aHsAXiH9YDPXLRF4Br93w5QQw9E433Rt2Ov_tAg0t_NbTlMjf5r3Vzg3byHNdoeGg
[2021-12-30 23:12:21.755][3269492][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:167] custom-jwt: Verifying JWT token of issuer https://myissuer
[2021-12-30 23:12:21.755][3269492][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:315] custom-jwt: JWT token verification completed with: OK
[2021-12-30 23:12:21.755][3269492][debug][jwt] [source/extensions/filters/http/jwt_authn/filter.cc:110] Jwt authentication completed with: OK
[2021-12-30 23:12:21.755][3269492][warning][wasm] [source/extensions/common/wasm/context.cc:1170] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:80]::onCreate() onCreate 2
[2021-12-30 23:12:21.756][3269492][debug][wasm] [source/extensions/common/wasm/context.cc:1164] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:83]::onRequestHeaders() onRequestHeaders 2
[2021-12-30 23:12:21.756][3269492][debug][wasm] [source/extensions/common/wasm/context.cc:1164] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:86]::onRequestHeaders() headers: 8
[2021-12-30 23:12:21.756][3269492][debug][wasm] [source/extensions/common/wasm/context.cc:1164] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:88]::onRequestHeaders() :authority -> http.domain.com
[2021-12-30 23:12:21.756][3269492][debug][wasm] [source/extensions/common/wasm/context.cc:1164] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:88]::onRequestHeaders() :path -> /get
[2021-12-30 23:12:21.756][3269492][debug][wasm] [source/extensions/common/wasm/context.cc:1164] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:88]::onRequestHeaders() :method -> GET
[2021-12-30 23:12:21.756][3269492][debug][wasm] [source/extensions/common/wasm/context.cc:1164] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:88]::onRequestHeaders() :scheme -> https
[2021-12-30 23:12:21.756][3269492][debug][wasm] [source/extensions/common/wasm/context.cc:1164] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:88]::onRequestHeaders() user-agent -> curl/7.79.1
[2021-12-30 23:12:21.756][3269492][debug][wasm] [source/extensions/common/wasm/context.cc:1164] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:88]::onRequestHeaders() accept -> */*
[2021-12-30 23:12:21.756][3269492][debug][wasm] [source/extensions/common/wasm/context.cc:1164] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:88]::onRequestHeaders() x-forwarded-proto -> https
[2021-12-30 23:12:21.756][3269492][debug][wasm] [source/extensions/common/wasm/context.cc:1164] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:88]::onRequestHeaders() x-request-id -> bdea9fac-199b-428e-a84c-5123885776c5
[2021-12-30 23:12:21.756][3269492][debug][wasm] [source/extensions/common/wasm/context.cc:1164] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:96]::onRequestHeaders()  x5t#S256 -> kV_FTD_BllHKImAMlqqbEm6LoHO0QYWATO5f823YckA
[2021-12-30 23:12:21.756][3269492][debug][wasm] [source/extensions/common/wasm/context.cc:1164] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:103]::onRequestHeaders()  subject_peer_certificate: CN=sts.domain.com,OU=Enterprise,O=Google,C=US
[2021-12-30 23:12:21.756][3269492][debug][wasm] [source/extensions/common/wasm/context.cc:1164] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:114]::onRequestHeaders() sha256_peer_certificate_digest: kV_FTD_BllHKImAMlqqbEm6LoHO0QYWATO5f823YckA
[2021-12-30 23:12:21.756][3269492][debug][wasm] [source/extensions/common/wasm/context.cc:1164] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:121]::onRequestHeaders() sha256_peer_certificate_digest and digest_from_cbf_header matched
[2021-12-30 23:12:21.756][3269492][debug][router] [source/common/router/router.cc:457] [C0][S13779638144948351405] cluster 'service_httpbin' match for URL '/get'
[2021-12-30 23:12:21.756][3269492][debug][router] [source/common/router/router.cc:673] [C0][S13779638144948351405] router decoding headers:
':authority', 'http.domain.com'
':path', '/get'
':method', 'GET'
':scheme', 'https'
'user-agent', 'curl/7.79.1'
'accept', '*/*'
'x-forwarded-proto', 'https'
'x-request-id', 'bdea9fac-199b-428e-a84c-5123885776c5'
'x-envoy-expected-rq-timeout-ms', '15000'

[2021-12-30 23:12:21.756][3269492][debug][pool] [source/common/http/conn_pool_base.cc:74] queueing stream due to no available connections
[2021-12-30 23:12:21.756][3269492][debug][pool] [source/common/conn_pool/conn_pool_base.cc:255] trying to create new connection
[2021-12-30 23:12:21.756][3269492][debug][pool] [source/common/conn_pool/conn_pool_base.cc:143] creating a new connection
[2021-12-30 23:12:21.756][3269492][debug][client] [source/common/http/codec_client.cc:60] [C1] connecting
[2021-12-30 23:12:21.756][3269492][debug][connection] [source/common/network/connection_impl.cc:890] [C1] connecting to 34.227.211.26:80
[2021-12-30 23:12:21.756][3269492][debug][connection] [source/common/network/connection_impl.cc:909] [C1] connection in progress
[2021-12-30 23:12:21.780][3269492][debug][connection] [source/common/network/connection_impl.cc:672] [C1] connected
[2021-12-30 23:12:21.780][3269492][debug][client] [source/common/http/codec_client.cc:88] [C1] connected
[2021-12-30 23:12:21.780][3269492][debug][pool] [source/common/conn_pool/conn_pool_base.cc:293] [C1] attaching to next stream
[2021-12-30 23:12:21.780][3269492][debug][pool] [source/common/conn_pool/conn_pool_base.cc:176] [C1] creating stream
[2021-12-30 23:12:21.780][3269492][debug][router] [source/common/router/upstream_request.cc:416] [C0][S13779638144948351405] pool ready
[2021-12-30 23:12:21.793][3269492][debug][router] [source/common/router/router.cc:1285] [C0][S13779638144948351405] upstream headers complete: end_stream=false
[2021-12-30 23:12:21.794][3269492][debug][wasm] [source/extensions/common/wasm/context.cc:1164] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:127]::onResponseHeaders() onResponseHeaders 2
[2021-12-30 23:12:21.794][3269492][debug][wasm] [source/extensions/common/wasm/context.cc:1164] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:130]::onResponseHeaders() headers: 9
[2021-12-30 23:12:21.794][3269492][debug][wasm] [source/extensions/common/wasm/context.cc:1164] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:132]::onResponseHeaders() :status -> 200
[2021-12-30 23:12:21.794][3269492][debug][wasm] [source/extensions/common/wasm/context.cc:1164] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:132]::onResponseHeaders() date -> Fri, 31 Dec 2021 04:12:21 GMT
[2021-12-30 23:12:21.794][3269492][debug][wasm] [source/extensions/common/wasm/context.cc:1164] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:132]::onResponseHeaders() content-type -> application/json
[2021-12-30 23:12:21.794][3269492][debug][wasm] [source/extensions/common/wasm/context.cc:1164] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:132]::onResponseHeaders() content-length -> 309
[2021-12-30 23:12:21.794][3269492][debug][wasm] [source/extensions/common/wasm/context.cc:1164] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:132]::onResponseHeaders() connection -> keep-alive
[2021-12-30 23:12:21.794][3269492][debug][wasm] [source/extensions/common/wasm/context.cc:1164] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:132]::onResponseHeaders() server -> gunicorn/19.9.0
[2021-12-30 23:12:21.794][3269492][debug][wasm] [source/extensions/common/wasm/context.cc:1164] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:132]::onResponseHeaders() access-control-allow-origin -> *
[2021-12-30 23:12:21.794][3269492][debug][wasm] [source/extensions/common/wasm/context.cc:1164] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:132]::onResponseHeaders() access-control-allow-credentials -> true
[2021-12-30 23:12:21.794][3269492][debug][wasm] [source/extensions/common/wasm/context.cc:1164] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:132]::onResponseHeaders() x-envoy-upstream-service-time -> 36
[2021-12-30 23:12:21.794][3269492][debug][http] [source/common/http/conn_manager_impl.cc:1467] [C0][S13779638144948351405] encoding headers via codec (end_stream=false):
':status', '200'
'date', 'Fri, 31 Dec 2021 04:12:21 GMT'
'content-type', 'application/json'
'content-length', '309'
'server', 'envoy'
'access-control-allow-origin', '*'
'access-control-allow-credentials', 'true'
'x-envoy-upstream-service-time', '36'

[2021-12-30 23:12:21.795][3269492][debug][client] [source/common/http/codec_client.cc:132] [C1] response complete
[2021-12-30 23:12:21.795][3269492][warning][wasm] [source/extensions/common/wasm/context.cc:1170] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:151]::onLog() onLog 2
[2021-12-30 23:12:21.795][3269492][debug][jwt] [source/extensions/filters/http/jwt_authn/filter.cc:46] Called Filter : onDestroy
[2021-12-30 23:12:21.795][3269492][warning][wasm] [source/extensions/common/wasm/context.cc:1170] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:149]::onDone() onDone 2
[2021-12-30 23:12:21.795][3269492][warning][wasm] [source/extensions/common/wasm/context.cc:1170] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:153]::onDelete() onDelete 2
[2021-12-30 23:12:21.795][3269492][debug][pool] [source/common/http/http1/conn_pool.cc:53] [C1] response complete
```

Again, you should wait for the upstream changes