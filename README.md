## Envoy WASM and LUA filters for Certificate Bound Tokens

Envoy LUA and wasm filters that enforce very basic [Certificate Bound Tokens](https://connect2id.com/learn/token-binding).

The basic idea behind bound tokens is that the signed bearer token itself has information embedded within it which defines the transport/TLS client certificate that is presented.

That is, information provided within a presented client cert during mTLS with a resource server will be used to cross validate the bearer token which was encoded and bound to that certificate.

Binding the token to the cert reduces the security risk of bearer tokens which as the name suggests can be used by arbitrary callers.  With bound tokens, the call must also demonstrate that they are in possession of the client certificate.

In the easiest flow, the bearer token that is ultimately used against a resource gets minted by a service which will verify that the client is infact in possession of certificate.  One way to do that is to use the same mTLS certs to interact with the Authorization server that will eventually get used on the Resource Server.  The more complicated flows involve multiple certificates but those flows are not described here.

>> `12/1/20`: NOTE:  the wasm plugin is not yet ready.  It is pending implementation of [envoy issue#14229](https://github.com/envoyproxy/envoy/issues/14229).  However, i do describe how to build the plugin anyway.

>> `12/29/21`: the wasm plugin is still not ready since envoy wasm doesn't surface the cert signature.  However, i was able to modify envoy to emit those values and actually process them in the sample wasm binary below

>> `14/7/22`: [issue#14229](https://github.com/envoyproxy/envoy/issues/14229) merged so envoy+wasm can now enforce cert-boound access

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
b00d38a52273af0238406b74f8d26f8273252aded332d73b4842b2d2e666ba01

$ echo "b00d38a52273af0238406b74f8d26f8273252aded332d73b4842b2d2e666ba01" | xxd -r -p - | openssl enc -a | tr -d '=' | tr '/+' '_-'
sA04pSJzrwI4QGt0-NJvgnMlKt7TMtc7SEKy0uZmugE
```

Which eventually is sealed into a bearer token (JWT in this case) using the following claim:

```json
{
  "cnf": {
    "x5t#S256": "sA04pSJzrwI4QGt0-NJvgnMlKt7TMtc7SEKy0uZmugE"
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

2022/07/13 20:54:32 eyJhbGciOiJSUzI1NiIsImtpZCI6IjIiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2Zvby5iYXIiLCJleHAiOjE2ODg1MTg0NzIsImlhdCI6MTY1Nzc2MDA3MiwiaXNzIjoiaHR0cHM6Ly9teWlzc3VlciIsImNuZiI6eyJ4NXQjUzI1NiI6InNBMDRwU0p6cndJNFFHdDAtTkp2Z25NbEt0N1RNdGM3U0VLeTB1Wm11Z0UifX0.UKW4BUvudUG2g8zspchwafSASylig-GCf8ZNL3efcdxQ7MmuK2dod8X4AySJy4U1cTNL6kG81tLWFFrkrDTirm6rua45zhQ9p0ysuJgDhG7uJDF1IvbMRgj7VJzCir_8wv_99-JkJpQ9CWye0IxjIOgTUUbBTx2snrmHoJ8q-XKvGVVxN15IZJcZSFI1vfIV4x5_7HoCc9NT1CNyXnLzcvWFu4NIVaxxU1F9kx-5JiBeSZ5FN5h2uaryLvFfKSisgnlTM2e6Qro3EBNvHqfKeJ9YA0uZbpjf-SVAsqg4KS-7407elVORtuNXgt-Odv3M3LGfkAFYsy46cGbOi_W8Ow
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
  "exp": 1688518472,
  "iat": 1657760072,
  "iss": "https://myissuer",
  "cnf": {
    "x5t#S256": "sA04pSJzrwI4QGt0-NJvgnMlKt7TMtc7SEKy0uZmugE"
  }
}
```

export the value

```bash
export TOKEN=eyJhbGciOiJSUzI1NiIsImtpZCI6IjIiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2Zvby5iYXIiLCJleHAiOjE2ODg1MTgxMTcsImlhdCI6MTY1Nzc1OTcxNywiaXNzIjoiaHR0cHM6Ly9teWlzc3VlciIsImNuZiI6eyJ4NXQjUzI1NiI6InNBMDRwU0p6cndJNFFHdDAtTkp2Z25NbEt0N1RNdGM3U0VLeTB1Wm11Z0UifX0.tpZg6srTR2sFt9gca7fY1ufdEQksaNZLZJAE1DmTdgONLuqSa_ifyvL9_o_TZVse-hhqKPx0X91yve15ROP5rorMeadWjK2sNHKNzbflM7Sa00x1UfJtX7rOkKm8r3QPYfMqXn1Ptwl8sB1yocCbhtG4vkQp-H3_olT0kjG_mno0bki8S_y_CNwN0hAAaZqSxjPZGOLzmPwcrHzJa5HZ3WptmbtcDuBT1ImHEQEb4j2yQPR1cE8I-N2TwQSGGtClKOmjG4I8gYsPl1IG70gW8kd7yyd_0mn-Ztpn6qIcBAStfDNudVmsVspHyqe5kzhuB_O2_18UECpXVHU1V_ftzQ
```

## Get Envoy

Finally, get a copy of envoy that supports `wasm`

>> **NOTE**:  we are using `envoy 1.17`

```bash
docker cp `docker create envoyproxy/envoy-dev:latest`:/usr/local/bin/envoy /tmp/

#  (i used docker cp `docker create envoyproxy/envoy-dev@sha256:045063c5fe6f1209cb9cb56c092e50dfab2c6619715e5ee9b85425d13fecd124`:/usr/local/bin/envoy /tmp/)
```

### Deploy

We are now ready to startup envoy and give it all a go.  You can try either wasm (eventually) or lua 

Note, i've described how to build wasm below but thats just a placeholder until the feature with envoy described above is implemented.

### LUA

To test with `LUA`, simply run

```bash
/tmp/envoy -c lua.yaml -l debug
```

### CURL

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
[2022-07-13 21:00:54.941][2922772][debug][conn_handler] [source/server/active_tcp_listener.cc:142] [C0] new connection from 127.0.0.1:42440
[2022-07-13 21:00:54.946][2922772][debug][http] [source/common/http/conn_manager_impl.cc:299] [C0] new stream
[2022-07-13 21:00:54.946][2922772][debug][http] [source/common/http/conn_manager_impl.cc:904] [C0][S6139208093804265673] request headers complete (end_stream=true):
':authority', 'http.domain.com'
':path', '/get'
':method', 'GET'
'user-agent', 'curl/7.83.1'
'accept', '*/*'
'authorization', 'Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjIiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2Zvby5iYXIiLCJleHAiOjE2ODg1MTg0NzIsImlhdCI6MTY1Nzc2MDA3MiwiaXNzIjoiaHR0cHM6Ly9teWlzc3VlciIsImNuZiI6eyJ4NXQjUzI1NiI6InNBMDRwU0p6cndJNFFHdDAtTkp2Z25NbEt0N1RNdGM3U0VLeTB1Wm11Z0UifX0.UKW4BUvudUG2g8zspchwafSASylig-GCf8ZNL3efcdxQ7MmuK2dod8X4AySJy4U1cTNL6kG81tLWFFrkrDTirm6rua45zhQ9p0ysuJgDhG7uJDF1IvbMRgj7VJzCir_8wv_99-JkJpQ9CWye0IxjIOgTUUbBTx2snrmHoJ8q-XKvGVVxN15IZJcZSFI1vfIV4x5_7HoCc9NT1CNyXnLzcvWFu4NIVaxxU1F9kx-5JiBeSZ5FN5h2uaryLvFfKSisgnlTM2e6Qro3EBNvHqfKeJ9YA0uZbpjf-SVAsqg4KS-7407elVORtuNXgt-Odv3M3LGfkAFYsy46cGbOi_W8Ow'

[2022-07-13 21:00:54.946][2922772][debug][http] [source/common/http/filter_manager.cc:841] [C0][S6139208093804265673] request end stream
[2022-07-13 21:00:54.946][2922772][debug][connection] [./source/common/network/connection_impl.h:89] [C0] current connecting state: false
[2022-07-13 21:00:54.946][2922772][debug][jwt] [source/extensions/filters/http/jwt_authn/filter.cc:158] Called Filter : setDecoderFilterCallbacks
[2022-07-13 21:00:54.946][2922772][debug][jwt] [source/extensions/filters/http/jwt_authn/filter.cc:53] Called Filter : decodeHeaders
[2022-07-13 21:00:54.946][2922772][debug][jwt] [source/extensions/filters/http/jwt_authn/matcher.cc:71] Prefix requirement '/' matched.
[2022-07-13 21:00:54.946][2922772][debug][jwt] [source/extensions/filters/http/jwt_authn/extractor.cc:250] extract authorizationBearer 
[2022-07-13 21:00:54.946][2922772][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:133] custom-jwt: JWT authentication starts (allow_failed=false), tokens size=1
[2022-07-13 21:00:54.946][2922772][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:144] custom-jwt: startVerify: tokens size 1
[2022-07-13 21:00:54.946][2922772][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:157] custom-jwt: Parse Jwt eyJhbGciOiJSUzI1NiIsImtpZCI6IjIiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2Zvby5iYXIiLCJleHAiOjE2ODg1MTg0NzIsImlhdCI6MTY1Nzc2MDA3MiwiaXNzIjoiaHR0cHM6Ly9teWlzc3VlciIsImNuZiI6eyJ4NXQjUzI1NiI6InNBMDRwU0p6cndJNFFHdDAtTkp2Z25NbEt0N1RNdGM3U0VLeTB1Wm11Z0UifX0.UKW4BUvudUG2g8zspchwafSASylig-GCf8ZNL3efcdxQ7MmuK2dod8X4AySJy4U1cTNL6kG81tLWFFrkrDTirm6rua45zhQ9p0ysuJgDhG7uJDF1IvbMRgj7VJzCir_8wv_99-JkJpQ9CWye0IxjIOgTUUbBTx2snrmHoJ8q-XKvGVVxN15IZJcZSFI1vfIV4x5_7HoCc9NT1CNyXnLzcvWFu4NIVaxxU1F9kx-5JiBeSZ5FN5h2uaryLvFfKSisgnlTM2e6Qro3EBNvHqfKeJ9YA0uZbpjf-SVAsqg4KS-7407elVORtuNXgt-Odv3M3LGfkAFYsy46cGbOi_W8Ow
[2022-07-13 21:00:54.946][2922772][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:167] custom-jwt: Verifying JWT token of issuer https://myissuer
[2022-07-13 21:00:54.946][2922772][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:313] custom-jwt: JWT token verification completed with: OK
[2022-07-13 21:00:54.946][2922772][debug][jwt] [source/extensions/filters/http/jwt_authn/filter.cc:110] Jwt authentication completed with: OK
[2022-07-13 21:00:54.946][2922772][info][lua] [source/extensions/filters/http/lua/lua_filter.cc:763] script log: Peer Signature: sA04pSJzrwI4QGt0-NJvgnMlKt7TMtc7SEKy0uZmugE
[2022-07-13 21:00:54.946][2922772][info][lua] [source/extensions/filters/http/lua/lua_filter.cc:763] script log: JWT Signature: sA04pSJzrwI4QGt0-NJvgnMlKt7TMtc7SEKy0uZmugE
[2022-07-13 21:00:54.946][2922772][debug][lua] [source/extensions/filters/common/lua/lua.cc:39] coroutine finished
[2022-07-13 21:00:54.946][2922772][debug][router] [source/common/router/router.cc:467] [C0][S6139208093804265673] cluster 'service_httpbin' match for URL '/get'
[2022-07-13 21:00:54.947][2922772][debug][router] [source/common/router/router.cc:670] [C0][S6139208093804265673] router decoding headers:
':authority', 'http.domain.com'
':path', '/get'
':method', 'GET'
':scheme', 'https'
'user-agent', 'curl/7.83.1'
'accept', '*/*'
'x-forwarded-proto', 'https'
'x-request-id', 'a778cd6c-eeb0-4fe6-8e6f-36ac72cee345'
'x-envoy-expected-rq-timeout-ms', '15000'

[2022-07-13 21:00:54.947][2922772][debug][pool] [source/common/http/conn_pool_base.cc:78] queueing stream due to no available connections (ready=0 busy=0 connecting=0)
[2022-07-13 21:00:54.947][2922772][debug][pool] [source/common/conn_pool/conn_pool_base.cc:290] trying to create new connection
[2022-07-13 21:00:54.947][2922772][debug][pool] [source/common/conn_pool/conn_pool_base.cc:145] creating a new connection (connecting=0)
[2022-07-13 21:00:54.947][2922772][debug][connection] [./source/common/network/connection_impl.h:89] [C1] current connecting state: true
[2022-07-13 21:00:54.947][2922772][debug][client] [source/common/http/codec_client.cc:57] [C1] connecting
[2022-07-13 21:00:54.947][2922772][debug][connection] [source/common/network/connection_impl.cc:912] [C1] connecting to 34.227.213.82:80
[2022-07-13 21:00:54.947][2922772][debug][connection] [source/common/network/connection_impl.cc:931] [C1] connection in progress
[2022-07-13 21:00:54.952][2922772][debug][connection] [source/common/network/connection_impl.cc:683] [C1] connected
[2022-07-13 21:00:54.952][2922772][debug][client] [source/common/http/codec_client.cc:89] [C1] connected
[2022-07-13 21:00:54.952][2922772][debug][pool] [source/common/conn_pool/conn_pool_base.cc:327] [C1] attaching to next stream
[2022-07-13 21:00:54.952][2922772][debug][pool] [source/common/conn_pool/conn_pool_base.cc:181] [C1] creating stream
[2022-07-13 21:00:54.952][2922772][debug][router] [source/common/router/upstream_request.cc:422] [C0][S6139208093804265673] pool ready
[2022-07-13 21:00:54.962][2922772][debug][router] [source/common/router/router.cc:1351] [C0][S6139208093804265673] upstream headers complete: end_stream=false
[2022-07-13 21:00:54.962][2922772][debug][http] [source/common/http/conn_manager_impl.cc:1516] [C0][S6139208093804265673] encoding headers via codec (end_stream=false):
':status', '200'
'date', 'Thu, 14 Jul 2022 01:00:54 GMT'
'content-type', 'application/json'
'content-length', '310'
'server', 'envoy'
'access-control-allow-origin', '*'
'access-control-allow-credentials', 'true'
'x-envoy-upstream-service-time', '15'

[2022-07-13 21:00:54.962][2922772][debug][client] [source/common/http/codec_client.cc:126] [C1] response complete
```

### WASM


You can either use the wasm binary thats part of this repo or build your own:

to build your own,

```bash
 git clone https://github.com/envoyproxy/envoy.git
 rm -rf envoy/examples/wasm-cc/
 cp -R wasm-cc  envoy/examples/
 cd envoy
 # note i'm just guessing https://github.com/envoyproxy/envoy/issues/14229 is going to get included in 1.20.7
 git checkout tags/v1.20.7

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

```
/tmp/envoy -c wasm.yaml -l debug
```


(note, i've uploaded the binary to this page [here](https://storage.googleapis.com/pki.esodemoapp2.com/envoy_with_tokenbinding_wasm))

If you send in a curl request like the one above from LUA, you will see, you'll see the certificate fingerprints were extracted from the JWT and TLS session and compared.

```log
[2022-07-14 07:19:45.526][2953099][debug][wasm] [source/extensions/common/wasm/context.cc:1167] 
   wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:96]::onRequestHeaders()  
      x5t#S256 -> sA04pSJzrwI4QGt0-NJvgnMlKt7TMtc7SEKy0uZmugE

[2022-07-14 07:19:45.526][2953099][debug][wasm] [source/extensions/common/wasm/context.cc:1167] 
   wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:103]::onRequestHeaders()  
      subject_peer_certificate: CN=clientjwt.domain.com,OU=Enterprise,O=Google,C=US

[2022-07-14 07:19:45.526][2953099][debug][wasm] [source/extensions/common/wasm/context.cc:1167] 
   wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:114]::onRequestHeaders() 
      sha256_peer_certificate_digest: sA04pSJzrwI4QGt0-NJvgnMlKt7TMtc7SEKy0uZmugE

[2022-07-14 07:19:45.526][2953099][debug][wasm] [source/extensions/common/wasm/context.cc:1167] 
   wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:121]::onRequestHeaders() 
      sha256_peer_certificate_digest and digest_from_cnf_claim matched
```

The full wasm log

```log
[2022-07-14 07:19:45.521][2953099][debug][conn_handler] [source/server/active_tcp_listener.cc:147] [C0] new connection from 127.0.0.1:37392
[2022-07-14 07:19:45.525][2953099][debug][http] [source/common/http/conn_manager_impl.cc:304] [C0] new stream
[2022-07-14 07:19:45.525][2953099][debug][http] [source/common/http/conn_manager_impl.cc:909] [C0][S13957625050676133400] request headers complete (end_stream=true):
':authority', 'http.domain.com'
':path', '/get'
':method', 'GET'
'user-agent', 'curl/7.83.1'
'accept', '*/*'
'authorization', 'Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjIiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2Zvby5iYXIiLCJleHAiOjE2ODg1MTgxMTcsImlhdCI6MTY1Nzc1OTcxNywiaXNzIjoiaHR0cHM6Ly9teWlzc3VlciIsImNuZiI6eyJ4NXQjUzI1NiI6InNBMDRwU0p6cndJNFFHdDAtTkp2Z25NbEt0N1RNdGM3U0VLeTB1Wm11Z0UifX0.tpZg6srTR2sFt9gca7fY1ufdEQksaNZLZJAE1DmTdgONLuqSa_ifyvL9_o_TZVse-hhqKPx0X91yve15ROP5rorMeadWjK2sNHKNzbflM7Sa00x1UfJtX7rOkKm8r3QPYfMqXn1Ptwl8sB1yocCbhtG4vkQp-H3_olT0kjG_mno0bki8S_y_CNwN0hAAaZqSxjPZGOLzmPwcrHzJa5HZ3WptmbtcDuBT1ImHEQEb4j2yQPR1cE8I-N2TwQSGGtClKOmjG4I8gYsPl1IG70gW8kd7yyd_0mn-Ztpn6qIcBAStfDNudVmsVspHyqe5kzhuB_O2_18UECpXVHU1V_ftzQ'

[2022-07-14 07:19:45.525][2953099][debug][http] [source/common/http/filter_manager.cc:790] [C0][S13957625050676133400] request end stream
[2022-07-14 07:19:45.525][2953099][debug][connection] [./source/common/network/connection_impl.h:89] [C0] current connecting state: false
[2022-07-14 07:19:45.525][2953099][debug][jwt] [source/extensions/filters/http/jwt_authn/filter.cc:157] Called Filter : setDecoderFilterCallbacks
[2022-07-14 07:19:45.526][2953099][debug][jwt] [source/extensions/filters/http/jwt_authn/filter.cc:53] Called Filter : decodeHeaders
[2022-07-14 07:19:45.526][2953099][debug][jwt] [source/extensions/filters/http/jwt_authn/matcher.cc:71] Prefix requirement '/' matched.
[2022-07-14 07:19:45.526][2953099][debug][jwt] [source/extensions/filters/http/jwt_authn/extractor.cc:250] extract authorizationBearer 
[2022-07-14 07:19:45.526][2953099][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:133] custom-jwt: JWT authentication starts (allow_failed=false), tokens size=1
[2022-07-14 07:19:45.526][2953099][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:144] custom-jwt: startVerify: tokens size 1
[2022-07-14 07:19:45.526][2953099][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:157] custom-jwt: Parse Jwt eyJhbGciOiJSUzI1NiIsImtpZCI6IjIiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2Zvby5iYXIiLCJleHAiOjE2ODg1MTgxMTcsImlhdCI6MTY1Nzc1OTcxNywiaXNzIjoiaHR0cHM6Ly9teWlzc3VlciIsImNuZiI6eyJ4NXQjUzI1NiI6InNBMDRwU0p6cndJNFFHdDAtTkp2Z25NbEt0N1RNdGM3U0VLeTB1Wm11Z0UifX0.tpZg6srTR2sFt9gca7fY1ufdEQksaNZLZJAE1DmTdgONLuqSa_ifyvL9_o_TZVse-hhqKPx0X91yve15ROP5rorMeadWjK2sNHKNzbflM7Sa00x1UfJtX7rOkKm8r3QPYfMqXn1Ptwl8sB1yocCbhtG4vkQp-H3_olT0kjG_mno0bki8S_y_CNwN0hAAaZqSxjPZGOLzmPwcrHzJa5HZ3WptmbtcDuBT1ImHEQEb4j2yQPR1cE8I-N2TwQSGGtClKOmjG4I8gYsPl1IG70gW8kd7yyd_0mn-Ztpn6qIcBAStfDNudVmsVspHyqe5kzhuB_O2_18UECpXVHU1V_ftzQ
[2022-07-14 07:19:45.526][2953099][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:167] custom-jwt: Verifying JWT token of issuer https://myissuer
[2022-07-14 07:19:45.526][2953099][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:313] custom-jwt: JWT token verification completed with: OK
[2022-07-14 07:19:45.526][2953099][debug][jwt] [source/extensions/filters/http/jwt_authn/filter.cc:109] Jwt authentication completed with: OK
[2022-07-14 07:19:45.526][2953099][warning][wasm] [source/extensions/common/wasm/context.cc:1173] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:80]::onCreate() onCreate 2
[2022-07-14 07:19:45.526][2953099][debug][wasm] [source/extensions/common/wasm/context.cc:1167] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:83]::onRequestHeaders() onRequestHeaders 2
[2022-07-14 07:19:45.526][2953099][debug][wasm] [source/extensions/common/wasm/context.cc:1167] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:86]::onRequestHeaders() headers: 8
[2022-07-14 07:19:45.526][2953099][debug][wasm] [source/extensions/common/wasm/context.cc:1167] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:88]::onRequestHeaders() :authority -> http.domain.com
[2022-07-14 07:19:45.526][2953099][debug][wasm] [source/extensions/common/wasm/context.cc:1167] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:88]::onRequestHeaders() :path -> /get
[2022-07-14 07:19:45.526][2953099][debug][wasm] [source/extensions/common/wasm/context.cc:1167] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:88]::onRequestHeaders() :method -> GET
[2022-07-14 07:19:45.526][2953099][debug][wasm] [source/extensions/common/wasm/context.cc:1167] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:88]::onRequestHeaders() :scheme -> https
[2022-07-14 07:19:45.526][2953099][debug][wasm] [source/extensions/common/wasm/context.cc:1167] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:88]::onRequestHeaders() user-agent -> curl/7.83.1
[2022-07-14 07:19:45.526][2953099][debug][wasm] [source/extensions/common/wasm/context.cc:1167] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:88]::onRequestHeaders() accept -> */*
[2022-07-14 07:19:45.526][2953099][debug][wasm] [source/extensions/common/wasm/context.cc:1167] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:88]::onRequestHeaders() x-forwarded-proto -> https
[2022-07-14 07:19:45.526][2953099][debug][wasm] [source/extensions/common/wasm/context.cc:1167] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:88]::onRequestHeaders() x-request-id -> 62878778-bf15-4d55-a4b4-4858002d5035
[2022-07-14 07:19:45.526][2953099][debug][wasm] [source/extensions/common/wasm/context.cc:1167] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:96]::onRequestHeaders()  x5t#S256 -> sA04pSJzrwI4QGt0-NJvgnMlKt7TMtc7SEKy0uZmugE
[2022-07-14 07:19:45.526][2953099][debug][wasm] [source/extensions/common/wasm/context.cc:1167] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:103]::onRequestHeaders()  subject_peer_certificate: CN=clientjwt.domain.com,OU=Enterprise,O=Google,C=US
[2022-07-14 07:19:45.526][2953099][debug][wasm] [source/extensions/common/wasm/context.cc:1167] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:114]::onRequestHeaders() sha256_peer_certificate_digest: sA04pSJzrwI4QGt0-NJvgnMlKt7TMtc7SEKy0uZmugE
[2022-07-14 07:19:45.526][2953099][debug][wasm] [source/extensions/common/wasm/context.cc:1167] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:121]::onRequestHeaders() sha256_peer_certificate_digest and digest_from_cnf_claim matched
[2022-07-14 07:19:45.526][2953099][debug][router] [source/common/router/router.cc:471] [C0][S13957625050676133400] cluster 'service_httpbin' match for URL '/get'
[2022-07-14 07:19:45.526][2953099][debug][router] [source/common/router/router.cc:675] [C0][S13957625050676133400] router decoding headers:
':authority', 'http.domain.com'
':path', '/get'
':method', 'GET'
':scheme', 'https'
'user-agent', 'curl/7.83.1'
'accept', '*/*'
'x-forwarded-proto', 'https'
'x-request-id', '62878778-bf15-4d55-a4b4-4858002d5035'
'x-envoy-expected-rq-timeout-ms', '15000'

[2022-07-14 07:19:45.526][2953099][debug][pool] [source/common/http/conn_pool_base.cc:78] queueing stream due to no available connections (ready=0 busy=0 connecting=0)
[2022-07-14 07:19:45.526][2953099][debug][pool] [source/common/conn_pool/conn_pool_base.cc:290] trying to create new connection
[2022-07-14 07:19:45.526][2953099][debug][pool] [source/common/conn_pool/conn_pool_base.cc:145] creating a new connection (connecting=0)
[2022-07-14 07:19:45.526][2953099][debug][connection] [./source/common/network/connection_impl.h:89] [C1] current connecting state: true
[2022-07-14 07:19:45.526][2953099][debug][client] [source/common/http/codec_client.cc:57] [C1] connecting
[2022-07-14 07:19:45.526][2953099][debug][connection] [source/common/network/connection_impl.cc:924] [C1] connecting to 34.227.213.82:80
[2022-07-14 07:19:45.526][2953099][debug][connection] [source/common/network/connection_impl.cc:943] [C1] connection in progress
[2022-07-14 07:19:45.532][2953099][debug][connection] [source/common/network/connection_impl.cc:683] [C1] connected
[2022-07-14 07:19:45.532][2953099][debug][client] [source/common/http/codec_client.cc:89] [C1] connected
[2022-07-14 07:19:45.532][2953099][debug][pool] [source/common/conn_pool/conn_pool_base.cc:327] [C1] attaching to next stream
[2022-07-14 07:19:45.532][2953099][debug][pool] [source/common/conn_pool/conn_pool_base.cc:181] [C1] creating stream
[2022-07-14 07:19:45.533][2953099][debug][router] [source/common/router/upstream_request.cc:424] [C0][S13957625050676133400] pool ready
[2022-07-14 07:19:45.540][2953099][debug][router] [source/common/router/router.cc:1359] [C0][S13957625050676133400] upstream headers complete: end_stream=false
[2022-07-14 07:19:45.541][2953099][debug][wasm] [source/extensions/common/wasm/context.cc:1167] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:127]::onResponseHeaders() onResponseHeaders 2
[2022-07-14 07:19:45.541][2953099][debug][wasm] [source/extensions/common/wasm/context.cc:1167] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:130]::onResponseHeaders() headers: 9
[2022-07-14 07:19:45.541][2953099][debug][wasm] [source/extensions/common/wasm/context.cc:1167] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:132]::onResponseHeaders() :status -> 200
[2022-07-14 07:19:45.541][2953099][debug][wasm] [source/extensions/common/wasm/context.cc:1167] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:132]::onResponseHeaders() date -> Thu, 14 Jul 2022 11:19:45 GMT
[2022-07-14 07:19:45.541][2953099][debug][wasm] [source/extensions/common/wasm/context.cc:1167] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:132]::onResponseHeaders() content-type -> application/json
[2022-07-14 07:19:45.541][2953099][debug][wasm] [source/extensions/common/wasm/context.cc:1167] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:132]::onResponseHeaders() content-length -> 310
[2022-07-14 07:19:45.541][2953099][debug][wasm] [source/extensions/common/wasm/context.cc:1167] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:132]::onResponseHeaders() connection -> keep-alive
[2022-07-14 07:19:45.541][2953099][debug][wasm] [source/extensions/common/wasm/context.cc:1167] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:132]::onResponseHeaders() server -> gunicorn/19.9.0
[2022-07-14 07:19:45.541][2953099][debug][wasm] [source/extensions/common/wasm/context.cc:1167] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:132]::onResponseHeaders() access-control-allow-origin -> *
[2022-07-14 07:19:45.541][2953099][debug][wasm] [source/extensions/common/wasm/context.cc:1167] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:132]::onResponseHeaders() access-control-allow-credentials -> true
[2022-07-14 07:19:45.541][2953099][debug][wasm] [source/extensions/common/wasm/context.cc:1167] wasm log my_plugin tb_root_id tb_root_id: [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:132]::onResponseHeaders() x-envoy-upstream-service-time -> 14
[2022-07-14 07:19:45.541][2953099][debug][http] [source/common/http/conn_manager_impl.cc:1525] [C0][S13957625050676133400] encoding headers via codec (end_stream=false):
':status', '200'
'date', 'Thu, 14 Jul 2022 11:19:45 GMT'
'content-type', 'application/json'
'content-length', '310'
'server', 'envoy'
'access-control-allow-origin', '*'
'access-control-allow-credentials', 'true'
'x-envoy-upstream-service-time', '14'

[2022-07-14 07:19:45.541][2953099][debug][client] [source/common/http/codec_client.cc:127] [C1] response complete

```


