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
3a1ade601f49f8d1378f2d069483059126e27674116e75b5d858aeff1aac25b8

$ echo "3a1ade601f49f8d1378f2d069483059126e27674116e75b5d858aeff1aac25b8" | xxd -r -p - | openssl enc -a | tr -d '=' | tr '/+' '_-'
OhreYB9J-NE3jy0GlIMFkSbidnQRbnW12Fiu_xqsJbg
```

Which eventually is sealed into a bearer token (JWT in this case) using the following claim:

```json
{
  "cnf": {
    "x5t#S256": "OhreYB9J-NE3jy0GlIMFkSbidnQRbnW12Fiu_xqsJbg"
  }
}
```

The resource server is expected to verify the mTLS connections' client public key against this value.


### Bind certificate hash to bearer token

The golang application provided here will generate the `x5t` hash value and then encode it into a JWT token.  This token can then be used to contact the resource server

```bash
cd jwt_token/

$ $ go run main.go --capubFile ../certs/jwtca.crt \
    --caprivFile ../certs/jwtca.key   --clientpubCert ../certs/clientjwt.crt 

2024/04/01 18:45:22 eyJhbGciOiJSUzI1NiIsImtpZCI6IjEiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2Zvby5iYXIiLCJleHAiOjE3NDI3Njk5MjIsImlhdCI6MTcxMjAxMTUyMiwiaXNzIjoiaHR0cHM6Ly9teWlzc3VlciIsImNuZiI6eyJ4NXQjUzI1NiI6Ik9ocmVZQjlKLU5FM2p5MEdsSU1Ga1NiaWRuUVJiblcxMkZpdV94cXNKYmcifX0.MZcwh4KUgWtjAFhmTaoPaAsMxLem3DxuGXEZQOWgYAxBKiUZ_Mox6yzpJMShMQnBHf9aGFqgwrJuQNc49HBrA4_FvRHYBBrtcZqYPk314Hz9HsUdbi_r2NorCskSKW5edS0WcL4sRNHaW03maICwyzGd6cTJ2mD92P8jSJIwLd6z1aOGHwL8uUM7LflVw1I6j8DYjNfcHiBbFg4Kqmc0PvPrauyZaY2BjSM3wMdVMjXbkgPYi1x4HgJIzmZY9onMoiIqVPi3KxYcBAGbYux-nrqZlzzdMogXp7WWz4Cm3PE2FyRY0L7FvvbTuNjziD-is-Xr-Q2QdF8nta8Wvi0zYg
```

will give a token like

```json
{
  "alg": "RS256",
  "kid": "1",
  "typ": "JWT"
}
{
  "aud": "https://foo.bar",
  "exp": 1742769922,
  "iat": 1712011522,
  "iss": "https://myissuer",
  "cnf": {
    "x5t#S256": "OhreYB9J-NE3jy0GlIMFkSbidnQRbnW12Fiu_xqsJbg"
  }
}
```

export the value

```bash
export TOKEN=eyJhbGciOiJSUzI1NiIsImtpZCI6IjEiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2Zvby5iYXIiLCJleHAiOjE3NDI3Njk5MjIsImlhdCI6MTcxMjAxMTUyMiwiaXNzIjoiaHR0cHM6Ly9teWlzc3VlciIsImNuZiI6eyJ4NXQjUzI1NiI6Ik9ocmVZQjlKLU5FM2p5MEdsSU1Ga1NiaWRuUVJiblcxMkZpdV94cXNKYmcifX0.MZcwh4KUgWtjAFhmTaoPaAsMxLem3DxuGXEZQOWgYAxBKiUZ_Mox6yzpJMShMQnBHf9aGFqgwrJuQNc49HBrA4_FvRHYBBrtcZqYPk314Hz9HsUdbi_r2NorCskSKW5edS0WcL4sRNHaW03maICwyzGd6cTJ2mD92P8jSJIwLd6z1aOGHwL8uUM7LflVw1I6j8DYjNfcHiBbFg4Kqmc0PvPrauyZaY2BjSM3wMdVMjXbkgPYi1x4HgJIzmZY9onMoiIqVPi3KxYcBAGbYux-nrqZlzzdMogXp7WWz4Cm3PE2FyRY0L7FvvbTuNjziD-is-Xr-Q2QdF8nta8Wvi0zYg
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
  --cacert certs/root-ca.crt   https://http.domain.com:8080/get
```

In the envoy logs, you should see the jwt claims extracted and then validated:

```log
[2024-04-01 18:56:31.432][659854][debug][http] [source/common/http/conn_manager_impl.cc:393] [Tags: "ConnectionId":"0"] new stream
[2024-04-01 18:56:31.432][659854][debug][http] [source/common/http/conn_manager_impl.cc:1192] [Tags: "ConnectionId":"0","StreamId":"187153484289857783"] request headers complete (end_stream=true):
':authority', 'http.domain.com'
':path', '/get'
':method', 'GET'
'user-agent', 'curl/8.5.0'
'accept', '*/*'
'authorization', 'Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjEiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2Zvby5iYXIiLCJleHAiOjE3NDI3Njk5MjIsImlhdCI6MTcxMjAxMTUyMiwiaXNzIjoiaHR0cHM6Ly9teWlzc3VlciIsImNuZiI6eyJ4NXQjUzI1NiI6Ik9ocmVZQjlKLU5FM2p5MEdsSU1Ga1NiaWRuUVJiblcxMkZpdV94cXNKYmcifX0.MZcwh4KUgWtjAFhmTaoPaAsMxLem3DxuGXEZQOWgYAxBKiUZ_Mox6yzpJMShMQnBHf9aGFqgwrJuQNc49HBrA4_FvRHYBBrtcZqYPk314Hz9HsUdbi_r2NorCskSKW5edS0WcL4sRNHaW03maICwyzGd6cTJ2mD92P8jSJIwLd6z1aOGHwL8uUM7LflVw1I6j8DYjNfcHiBbFg4Kqmc0PvPrauyZaY2BjSM3wMdVMjXbkgPYi1x4HgJIzmZY9onMoiIqVPi3KxYcBAGbYux-nrqZlzzdMogXp7WWz4Cm3PE2FyRY0L7FvvbTuNjziD-is-Xr-Q2QdF8nta8Wvi0zYg'

[2024-04-01 18:56:31.432][659854][debug][jwt] [source/extensions/filters/http/jwt_authn/matcher.cc:71] Prefix requirement '/' matched.
[2024-04-01 18:56:31.432][659854][debug][jwt] [source/extensions/filters/http/jwt_authn/extractor.cc:255] extract authorizationBearer 
[2024-04-01 18:56:31.432][659854][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:162] custom-jwt: JWT authentication starts (allow_failed=false), tokens size=1
[2024-04-01 18:56:31.432][659854][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:173] custom-jwt: startVerify: tokens size 1
[2024-04-01 18:56:31.432][659854][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:191] custom-jwt: Parse Jwt eyJhbGciOiJSUzI1NiIsImtpZCI6IjEiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2Zvby5iYXIiLCJleHAiOjE3NDI3Njk5MjIsImlhdCI6MTcxMjAxMTUyMiwiaXNzIjoiaHR0cHM6Ly9teWlzc3VlciIsImNuZiI6eyJ4NXQjUzI1NiI6Ik9ocmVZQjlKLU5FM2p5MEdsSU1Ga1NiaWRuUVJiblcxMkZpdV94cXNKYmcifX0.MZcwh4KUgWtjAFhmTaoPaAsMxLem3DxuGXEZQOWgYAxBKiUZ_Mox6yzpJMShMQnBHf9aGFqgwrJuQNc49HBrA4_FvRHYBBrtcZqYPk314Hz9HsUdbi_r2NorCskSKW5edS0WcL4sRNHaW03maICwyzGd6cTJ2mD92P8jSJIwLd6z1aOGHwL8uUM7LflVw1I6j8DYjNfcHiBbFg4Kqmc0PvPrauyZaY2BjSM3wMdVMjXbkgPYi1x4HgJIzmZY9onMoiIqVPi3KxYcBAGbYux-nrqZlzzdMogXp7WWz4Cm3PE2FyRY0L7FvvbTuNjziD-is-Xr-Q2QdF8nta8Wvi0zYg
[2024-04-01 18:56:31.432][659854][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:202] custom-jwt: Verifying JWT token of issuer https://myissuer
[2024-04-01 18:56:31.432][659854][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:428] custom-jwt: JWT token verification completed with: OK
[2024-04-01 18:56:31.432][659854][debug][jwt] [source/extensions/filters/http/jwt_authn/filter.cc:111] Jwt authentication completed with: OK
[2024-04-01 18:56:31.433][659854][info][lua] [source/extensions/filters/http/lua/lua_filter.cc:920] script log: Peer Signature: OhreYB9J-NE3jy0GlIMFkSbidnQRbnW12Fiu_xqsJbg
[2024-04-01 18:56:31.433][659854][info][lua] [source/extensions/filters/http/lua/lua_filter.cc:920] script log: JWT Signature: OhreYB9J-NE3jy0GlIMFkSbidnQRbnW12Fiu_xqsJbg
[2024-04-01 18:56:31.433][659854][debug][lua] [source/extensions/filters/common/lua/lua.cc:39] coroutine finished
[2024-04-01 18:56:31.433][659854][debug][router] [source/common/router/router.cc:514] [Tags: "ConnectionId":"0","StreamId":"187153484289857783"] cluster 'service_httpbin' match for URL '/get'
[2024-04-01 18:56:31.433][659854][debug][router] [source/common/router/router.cc:731] [Tags: "ConnectionId":"0","StreamId":"187153484289857783"] router decoding headers:
':authority', 'http.domain.com'
':path', '/get'
':method', 'GET'
':scheme', 'https'
'user-agent', 'curl/8.5.0'
'accept', '*/*'
'x-forwarded-proto', 'https'
'x-request-id', '9681f752-1939-4b17-88c4-3b587e14d806'
'x-envoy-expected-rq-timeout-ms', '15000'

[2024-04-01 18:56:31.938][659854][debug][router] [source/common/router/router.cc:1506] [Tags: "ConnectionId":"0","StreamId":"187153484289857783"] upstream headers complete: end_stream=false
[2024-04-01 18:56:31.938][659854][debug][http] [source/common/http/conn_manager_impl.cc:1869] [Tags: "ConnectionId":"0","StreamId":"187153484289857783"] encoding headers via codec (end_stream=false):
':status', '200'
'date', 'Mon, 01 Apr 2024 22:56:31 GMT'
'content-type', 'application/json'
'content-length', '309'
'server', 'envoy'
'access-control-allow-origin', '*'
'access-control-allow-credentials', 'true'
'x-envoy-upstream-service-time', '505'

[2024-04-01 18:56:31.938][659854][debug][client] [source/common/http/codec_client.cc:128] [Tags: "ConnectionId":"1"] response complete
```

### WASM


You can either use the wasm binary thats part of this repo or build your own:

to build your own,

```bash
 git clone https://github.com/envoyproxy/envoy.git
 rm -rf envoy/examples/wasm-cc/
 cp -R wasm-cc  envoy/examples/
 cd envoy
 # note cert specs surfaced to envoy https://github.com/envoyproxy/envoy/issues/14229

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

```bash
/tmp/envoy -c wasm.yaml -l debug
```


(note, i've uploaded the binary to this page [here](https://storage.googleapis.com/pki.esodemoapp2.com/envoy_with_tokenbinding_wasm))

If you send in a curl request like the one above from LUA, you will see, you'll see the certificate fingerprints were extracted from the JWT and TLS session and compared.

```log

[2024-04-01 18:58:32.883][660700][debug][wasm] [source/extensions/common/wasm/context.cc:1184] wasm log my_plugin tb_root_id tb_root_id: 

   [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:88]::onRequestHeaders() x-request-id -> b5d8625b-8afd-4915-9a75-dad24c563441

[2024-04-01 18:58:32.883][660700][debug][wasm] [source/extensions/common/wasm/context.cc:1184] wasm log my_plugin tb_root_id tb_root_id: 
   [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:96]::onRequestHeaders()  x5t#S256 -> OhreYB9J-NE3jy0GlIMFkSbidnQRbnW12Fiu_xqsJbg

[2024-04-01 18:58:32.883][660700][debug][wasm] [source/extensions/common/wasm/context.cc:1184] wasm log my_plugin tb_root_id tb_root_id: 
   [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:103]::onRequestHeaders()  subject_peer_certificate: CN=clientjwt.domain.com,OU=Enterprise,O=Google,L=US

[2024-04-01 18:58:32.883][660700][debug][wasm] [source/extensions/common/wasm/context.cc:1184] wasm log my_plugin tb_root_id tb_root_id: 
   [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:115]::onRequestHeaders() sha256_peer_certificate_digest: OhreYB9J-NE3jy0GlIMFkSbidnQRbnW12Fiu_xqsJbg
   
[2024-04-01 18:58:32.883][660700][debug][wasm] [source/extensions/common/wasm/context.cc:1184] wasm log my_plugin tb_root_id tb_root_id: 
   [examples/wasm-cc/envoy_filter_http_wasm_tokenbinding.cc:123]::onRequestHeaders() sha256_peer_certificate_digest and digest_from_cnf_claim matched

```



