## Envoy WASM filter for Certificate Bound Tokens

Envoy LUA and wasm filters that enforce very basic [Certificate Bound Tokens](https://connect2id.com/learn/token-binding).

The basic idea behind bound tokens is that the signed bearer token itself has information embedded within it which defines the transport/TLS client certificate that is presented.

That is, information provided within a presented client cert during mTLS with a resource server will be used to cross validate the bearer token which was encoded and bound to that certificate.

Binding the token to the cert reduces the security risk of bearer tokens which as the name suggests can be used by arbitrary callers.  With bound tokens, the call must also demonstrate that they are in possession of the client certificate.

In the easiest flow, the bearer token that is ultimately used against a resource gets minted by a service which will verify that the client is infact in possession of certificate.  One way to do that is to use the same mTLS certs to interact with the Authorization server that will eventually get used on the Resource Server.  The more complicated flows involve multiple certificates but those flows are not described here.

>> `12/1/20`: NOTE:  the wasm plugin is not yet ready.  It is pending implementation of [envoy issue#14229](https://github.com/envoyproxy/envoy/issues/14229).  However, i do describe how to build the plugin anyway.

---

### Background

There are two variations of bound tokens described in this article that i'm using *together* (which isn't ofcourse necessary)

- 1. `OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens` [rfc 8705](https://tools.ietf.org/html/rfc8705)

In this mode, a specific claim directly includes the hash of the public certificate that will be used during mTLS.

For example, if the public cert used by the client is `clientjwt.crt`, then the thumbprint is calculate as such:

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
  // rest of jwt
  "cbf": {
    "x5t#S256": "kV_FTD_BllHKImAMlqqbEm6LoHO0QYWATO5f823YckA"
  }
}
```

so export that value

```bash
export x5t=kV_FTD_BllHKImAMlqqbEm6LoHO0QYWATO5f823YckA
```

The resource server is expected to verify the mTLS connections' client public key against this value.

- 2. `OAuth 2.0 Token Binding`

In this mechanism, the public certificate gets encoded within a standard structure (`TokenBindingMessage`) and as an http header value.
The resource server is expected to decode the TokenBindingMessage, extract an embedded ID field as well as the public certificate, compare that to the mTLS session and finally vierify the ID's hash value to an embedded field in the bearer token.

The protocols are described here
* `Token Binding over HTTP` [rfc 8437](https://tools.ietf.org/html/rfc8473)
   Defines `Sec-Token-Binding` Header

* `The Token Binding Protocol Version 1.0` [rfc 8471](https://tools.ietf.org/html/rfc8471)
   Defines `TokenBindingMessage`

* `OAuth 2.0 Token Binding` [draft-ietf-oauth-token-binding-08](https://tools.ietf.org/html/draft-ietf-oauth-token-binding-08)

*  `Transport Layer Security (TLS) Extension for Token Binding Protocol Negotiation` [rfc 8472](https://tools.ietf.org/html/rfc8472)

The bearer token will have an embedded field denoting which TokenBindingMessage is valid to check against:
```
 The value of the "tbh"
   member is the base64url encoding of the SHA-256 hash of the Token 
   Binding ID.  All trailing pad '=' characters are omitted from the
   encoded value and no line breaks, whitespace, or other additional
   characters are included.
```

For example, the provided bearer token may look something like this:

```json
{
  // rest of jwt
  "cbf": {
    "tbh": "dBPwPU6FpL1xgsUfqxZOMe4fXkR1UINjx3DK2AkNwSs",
  }
}
```
### Generate TokenBindingMessage and Binding Hash

Generating a `TokenBindingMessage` is described in the RFC above and to date, i've only found a java implementation here:

- [com.pingidentity.oss.unbearable.messages.TokenBindingMessage](https://github.com/pingidentity/token-binding-java)
- [Token Binding Protocol Negotiation TLS Extension support for Java 8](https://github.com/pingidentity/java8-token-binding-negotiation)

I've provided a utility program which will generate the `TokenBindingMessage` and `tbh` value.

The utility application will generate the binding message and hash using the certificate that will be used for mTLS (`certs/clientjwt_pub.der`, `certs/clientjwt_riv.der`)

```bash
$ cd gen_tbf/
$ mvn clean install exec:java -q

EKM: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwUj1lCTQsvR0cfe80lmSWqWQa835ogbxbNjcrVpINw6jmHpPE8MmKCdRlmIHydMsDC8rfPqo01DM_aEmsz1Ws6dHJaq0L_Do4IffSkeSfGSmCgftBFfF9cUnyRgU8_5BFPwJrHm_1ecRvlSn43M5NDGmYlqcKzGfK6IL4L77RgRU55_4e2E2caLmEX_PT0Ph3UO4aG5XHqTw9cAWfp1Zk1vHiOpW5uT4mUJcpcUThP5XCz7U0yqyKzsEhIGeojaR55dq8ID_DLt0RaykCPV--M8PGSpm2mQnyOBmmXBGopvESCZZITRZHZfLjb7PyLaRnhdeRLHOHW3lsnHyZ83QOQIDAQAB

Sec-Token-Binding: Ag4AAAEGAQDBSPWUJNCy9HRx97zSWZJapZBrzfmiBvFs2NytWkg3DqOYek8TwyYoJ1GWYgfJ0ywMLyt8-qjTUMz9oSazPVazp0clqrQv8Ojgh99KR5J8ZKYKB-0EV8X1xSfJGBTz_kEU_Amseb_V5xG-VKfjczk0MaZiWpwrMZ8rogvgvvtGBFTnn_h7YTZxouYRf89PQ-HdQ7hoblcepPD1wBZ-nVmTW8eI6lbm5PiZQlylxROE_lcLPtTTKrIrOwSEgZ6iNpHnl2rwgP8Mu3RFrKQI9X74zw8ZKmbaZCfI4GaZcEaim8RIJlkhNFkdl8uNvs_ItpGeF15Esc4dbeWycfJnzdA5AwEAAQEAiO95gLlauIdYDQ1N647ELVnI-gykzW7oWC0U5IUMlJo-xbLouIv1AsTc4n8CaERUzZ1ezdXGMY-E3FBeJ1uxlF5UtCzjoRdvduMgpXJYryaJrZqCYbd5zR5JWKDaZxWFjSam7CtDqCKvyLEkXNcu4tL_rEZUFIsb3M-zJGMSuhp3NdfEwjbXNgXYDAf7frgrF1wrLA9E2oFfbz41EO3_Yu8i_ZGElsnhxogHi-GJcUoCAz79h7JFUo5q_cUcBsor_Gl8IwTLwcd85Xxdow2soUOqZ1qoP07J62cX7-LlZmDk0EpY9FmtUEO06eQ_nMMKWqxDQhR3SsEgw-Z1otVtTQAA

TBH: dBPwPU6FpL1xgsUfqxZOMe4fXkR1UINjx3DK2AkNwSs
VALID
```

The outputs show the public key used, the header value and hash to trasmit.  Export those values in a shell:

```bash
export secTokenBinding=Ag4AAAEGAQDBSPWUJNCy9HRx97zSWZJapZBrzfmiBvFs2NytWkg3DqOYek8TwyYoJ1GWYgfJ0ywMLyt8-qjTUMz9oSazPVazp0clqrQv8Ojgh99KR5J8ZKYKB-0EV8X1xSfJGBTz_kEU_Amseb_V5xG-VKfjczk0MaZiWpwrMZ8rogvgvvtGBFTnn_h7YTZxouYRf89PQ-HdQ7hoblcepPD1wBZ-nVmTW8eI6lbm5PiZQlylxROE_lcLPtTTKrIrOwSEgZ6iNpHnl2rwgP8Mu3RFrKQI9X74zw8ZKmbaZCfI4GaZcEaim8RIJlkhNFkdl8uNvs_ItpGeF15Esc4dbeWycfJnzdA5AwEAAQEAiO95gLlauIdYDQ1N647ELVnI-gykzW7oWC0U5IUMlJo-xbLouIv1AsTc4n8CaERUzZ1ezdXGMY-E3FBeJ1uxlF5UtCzjoRdvduMgpXJYryaJrZqCYbd5zR5JWKDaZxWFjSam7CtDqCKvyLEkXNcu4tL_rEZUFIsb3M-zJGMSuhp3NdfEwjbXNgXYDAf7frgrF1wrLA9E2oFfbz41EO3_Yu8i_ZGElsnhxogHi-GJcUoCAz79h7JFUo5q_cUcBsor_Gl8IwTLwcd85Xxdow2soUOqZ1qoP07J62cX7-LlZmDk0EpY9FmtUEO06eQ_nMMKWqxDQhR3SsEgw-Z1otVtTQAA

export tbh=dBPwPU6FpL1xgsUfqxZOMe4fXkR1UINjx3DK2AkNwSs
```

### Bind certificate hash and TokenBindingMessage to bearer token

At this point we are ready to bind values into the bearer token.  I've added in another utility program which simulates the Authorization Server.  We will provide it with the generated `tbh` and crate the `x5t` value using the public cert provided (in reality, the Authorization server will generate these on its own using the certs over mTLS).

The command is shown below.  Note, we are using the client public cert to generate `x5t`, the `tbh` value from the java program above (its done separately since i dont' know of golang implementation of TokenBindingMessage)...and finally, the whole thing is signed by the private key for a CA.


```bash
$ $ go run main.go --capubFile ../certs/tls-ca.crt   --caprivFile ../certs/tls-ca.key   --clientpubCert ../certs/clientjwt.crt   --tbh dBPwPU6FpL1xgsUfqxZOMe4fXkR1UINjx3DK2AkNwSs

2020/12/01 11:49:35 eyJhbGciOiJSUzI1NiIsImtpZCI6IjIiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2Zvby5iYXIiLCJleHAiOjE2Mzc1OTk3NzUsImlhdCI6MTYwNjg0MTM3NSwiaXNzIjoiaHR0cHM6Ly9teWlzc3VlciIsImNiZiI6eyJ0YmgiOiJkQlB3UFU2RnBMMXhnc1VmcXhaT01lNGZYa1IxVUlOangzREsyQWtOd1NzIiwieDV0I1MyNTYiOiJrVl9GVERfQmxsSEtJbUFNbHFxYkVtNkxvSE8wUVlXQVRPNWY4MjNZY2tBIn19.oxGoxj4NpJdxzNMv9DV9-WyHF06q32xrwJOiCkhTqB450KNn_v4-znNbCjyFEMIpX_auR3XC_u7ev9LMXJ2aZakcg6VL1JNuAeWCd7Y10V_sKNEmKfRApl7k3NCJ2uWEfZdEvvZriO6vv3cClaZBzI10gkq6U5EvOcI-6OEKeVYYWZot-5Jm82e01MIJo_3YNi-LwhhoSg6APCe_uZdmIl3NFljtkoKmjYCT5RpFvWuuOvUwEu9L2EAaOCB-KAm2dp2YDK7cwscgCas4WHvNk9kh3ih8DtAutFfbXXFUgqISkwCD9UsSOgF2f5ZQvptHdRJCcHi_7CCTDaLM_UrWZA
```

export the value

```bash
export TOKEN=eyJhbGciOiJSUzI1NiIsImtpZCI6IjIiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2Zvby5iYXIiLCJleHAiOjE2Mzc1OTk3NzUsImlhdCI6MTYwNjg0MTM3NSwiaXNzIjoiaHR0cHM6Ly9teWlzc3VlciIsImNiZiI6eyJ0YmgiOiJkQlB3UFU2RnBMMXhnc1VmcXhaT01lNGZYa1IxVUlOangzREsyQWtOd1NzIiwieDV0I1MyNTYiOiJrVl9GVERfQmxsSEtJbUFNbHFxYkVtNkxvSE8wUVlXQVRPNWY4MjNZY2tBIn19.oxGoxj4NpJdxzNMv9DV9-WyHF06q32xrwJOiCkhTqB450KNn_v4-znNbCjyFEMIpX_auR3XC_u7ev9LMXJ2aZakcg6VL1JNuAeWCd7Y10V_sKNEmKfRApl7k3NCJ2uWEfZdEvvZriO6vv3cClaZBzI10gkq6U5EvOcI-6OEKeVYYWZot-5Jm82e01MIJo_3YNi-LwhhoSg6APCe_uZdmIl3NFljtkoKmjYCT5RpFvWuuOvUwEu9L2EAaOCB-KAm2dp2YDK7cwscgCas4WHvNk9kh3ih8DtAutFfbXXFUgqISkwCD9UsSOgF2f5ZQvptHdRJCcHi_7CCTDaLM_UrWZA
```

Notice the JWT issued includes claims from both mechanism:

```json
{
  "alg": "RS256",
  "kid": "2",
  "typ": "JWT"
}.
{
  "aud": "https://foo.bar",
  "exp": 1637599775,
  "iat": 1606841375,
  "iss": "https://myissuer",
  "cbf": {
    "tbh": "dBPwPU6FpL1xgsUfqxZOMe4fXkR1UINjx3DK2AkNwSs",
    "x5t#S256": "kV_FTD_BllHKImAMlqqbEm6LoHO0QYWATO5f823YckA"
  }
}
```

## Get Envoy

Finally, get a copy of envoy that supports `wasm`
```
docker cp `docker create envoyproxy/envoy-dev:latest`:/usr/local/bin/envoy /tmp/
```

## Deploy

We are now ready to startup envoy and give it all a go.  You can try either wasm (eventually) or lua 

Note, i've described how to build wasm below but thats just a placeholder until the feature with envoy described above is implemented.

### LUA

To test with `LUA`, simply run

```bash
/tmp/envoy -c lua.yaml -l debug
```

The LUA script only validates the `x5t` field and does not go into decoding/unmarshalling `Sec-Token-Binding` and comparing that to `tbh`.  That is way more LUA then i know how to do and would rather just use wasm for.  At the moment, i left it in just to show where you woudl do that in LUA.

### WASM

>> 12/1/20:  wasm based tokenbinding is not yet implemented and is pending [https://github.com/envoyproxy/envoy/issues/14229](https://github.com/envoyproxy/envoy/issues/14229). 

Skip this step for now
#### Envoy-wasm

copy provided source and build (you'll need [bazel](https://bazel.build/))

```bash
git clone https://github.com/envoyproxy/envoy.git
cp -R envoy_wasm/examples/wasm-cc/* envoy/examples/wasm-cc/

cd envoy 
bazel build //examples/wasm-cc:envoy_filter_http_wasm_example.wasm
cd ../
```


## CURL

Finally invoke the endpoint

```bash
echo $TOKEN
echo $secTokenBinding
curl -v -H "Authorization: Bearer $TOKEN" \
  -H "host: http.domain.com" \
  -H "Sec-Token-Binding: $secTokenBinding" \
  --resolve  http.domain.com:8080:127.0.0.1 \
  --cert certs/clientjwt.crt \
  --key certs/clientjwt.key  \
  --cacert certs/tls-ca.crt   https://http.domain.com:8080/get
```

In the envoy logs, you should see the jwt claims extracted and then validated:

```log
[2020-12-01 11:55:46.362][2027594][debug][jwt] [source/extensions/filters/http/jwt_authn/filter.cc:109] Jwt authentication completed with: OK
[2020-12-01 11:55:46.363][2027594][info][lua] [source/extensions/filters/http/lua/lua_filter.cc:745] script log: Peer Signature: kV_FTD_BllHKImAMlqqbEm6LoHO0QYWATO5f823YckA
[2020-12-01 11:55:46.363][2027594][info][lua] [source/extensions/filters/http/lua/lua_filter.cc:745] script log: JWT Signature: kV_FTD_BllHKImAMlqqbEm6LoHO0QYWATO5f823YckA
```

```log
[2020-12-01 11:55:46.362][2027594][debug][http] [source/common/http/conn_manager_impl.cc:254] [C1] new stream
[2020-12-01 11:55:46.362][2027594][debug][http] [source/common/http/conn_manager_impl.cc:895] [C1][S11931256139829432601] request headers complete (end_stream=true):
':authority', 'http.domain.com'
':path', '/get'
':method', 'GET'
'user-agent', 'curl/7.72.0'
'accept', '*/*'
'authorization', 'Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjIiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2Zvby5iYXIiLCJleHAiOjE2Mzc1OTk3NzUsImlhdCI6MTYwNjg0MTM3NSwiaXNzIjoiaHR0cHM6Ly9teWlzc3VlciIsImNiZiI6eyJ0YmgiOiJkQlB3UFU2RnBMMXhnc1VmcXhaT01lNGZYa1IxVUlOangzREsyQWtOd1NzIiwieDV0I1MyNTYiOiJrVl9GVERfQmxsSEtJbUFNbHFxYkVtNkxvSE8wUVlXQVRPNWY4MjNZY2tBIn19.oxGoxj4NpJdxzNMv9DV9-WyHF06q32xrwJOiCkhTqB450KNn_v4-znNbCjyFEMIpX_auR3XC_u7ev9LMXJ2aZakcg6VL1JNuAeWCd7Y10V_sKNEmKfRApl7k3NCJ2uWEfZdEvvZriO6vv3cClaZBzI10gkq6U5EvOcI-6OEKeVYYWZot-5Jm82e01MIJo_3YNi-LwhhoSg6APCe_uZdmIl3NFljtkoKmjYCT5RpFvWuuOvUwEu9L2EAaOCB-KAm2dp2YDK7cwscgCas4WHvNk9kh3ih8DtAutFfbXXFUgqISkwCD9UsSOgF2f5ZQvptHdRJCcHi_7CCTDaLM_UrWZA'
'sec-token-binding', 'Ag4AAAEGAQDBSPWUJNCy9HRx97zSWZJapZBrzfmiBvFs2NytWkg3DqOYek8TwyYoJ1GWYgfJ0ywMLyt8-qjTUMz9oSazPVazp0clqrQv8Ojgh99KR5J8ZKYKB-0EV8X1xSfJGBTz_kEU_Amseb_V5xG-VKfjczk0MaZiWpwrMZ8rogvgvvtGBFTnn_h7YTZxouYRf89PQ-HdQ7hoblcepPD1wBZ-nVmTW8eI6lbm5PiZQlylxROE_lcLPtTTKrIrOwSEgZ6iNpHnl2rwgP8Mu3RFrKQI9X74zw8ZKmbaZCfI4GaZcEaim8RIJlkhNFkdl8uNvs_ItpGeF15Esc4dbeWycfJnzdA5AwEAAQEAiO95gLlauIdYDQ1N647ELVnI-gykzW7oWC0U5IUMlJo-xbLouIv1AsTc4n8CaERUzZ1ezdXGMY-E3FBeJ1uxlF5UtCzjoRdvduMgpXJYryaJrZqCYbd5zR5JWKDaZxWFjSam7CtDqCKvyLEkXNcu4tL_rEZUFIsb3M-zJGMSuhp3NdfEwjbXNgXYDAf7frgrF1wrLA9E2oFfbz41EO3_Yu8i_ZGElsnhxogHi-GJcUoCAz79h7JFUo5q_cUcBsor_Gl8IwTLwcd85Xxdow2soUOqZ1qoP07J62cX7-LlZmDk0EpY9FmtUEO06eQ_nMMKWqxDQhR3SsEgw-Z1otVtTQAA'

[2020-12-01 11:55:46.362][2027594][debug][http] [source/common/http/filter_manager.cc:699] [C1][S11931256139829432601] request end stream
[2020-12-01 11:55:46.362][2027594][debug][jwt] [source/extensions/filters/http/jwt_authn/filter.cc:150] Called Filter : setDecoderFilterCallbacks
[2020-12-01 11:55:46.362][2027594][debug][jwt] [source/extensions/filters/http/jwt_authn/filter.cc:54] Called Filter : decodeHeaders
[2020-12-01 11:55:46.362][2027594][debug][jwt] [source/extensions/filters/http/jwt_authn/matcher.cc:70] Prefix requirement '/' matched.
[2020-12-01 11:55:46.362][2027594][debug][jwt] [source/extensions/filters/http/jwt_authn/extractor.cc:190] extract authorizationBearer 
[2020-12-01 11:55:46.362][2027594][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:127] custom-jwt: JWT authentication starts (allow_failed=false), tokens size=1
[2020-12-01 11:55:46.362][2027594][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:138] custom-jwt: startVerify: tokens size 1
[2020-12-01 11:55:46.362][2027594][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:143] custom-jwt: Parse Jwt eyJhbGciOiJSUzI1NiIsImtpZCI6IjIiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2Zvby5iYXIiLCJleHAiOjE2Mzc1OTk3NzUsImlhdCI6MTYwNjg0MTM3NSwiaXNzIjoiaHR0cHM6Ly9teWlzc3VlciIsImNiZiI6eyJ0YmgiOiJkQlB3UFU2RnBMMXhnc1VmcXhaT01lNGZYa1IxVUlOangzREsyQWtOd1NzIiwieDV0I1MyNTYiOiJrVl9GVERfQmxsSEtJbUFNbHFxYkVtNkxvSE8wUVlXQVRPNWY4MjNZY2tBIn19.oxGoxj4NpJdxzNMv9DV9-WyHF06q32xrwJOiCkhTqB450KNn_v4-znNbCjyFEMIpX_auR3XC_u7ev9LMXJ2aZakcg6VL1JNuAeWCd7Y10V_sKNEmKfRApl7k3NCJ2uWEfZdEvvZriO6vv3cClaZBzI10gkq6U5EvOcI-6OEKeVYYWZot-5Jm82e01MIJo_3YNi-LwhhoSg6APCe_uZdmIl3NFljtkoKmjYCT5RpFvWuuOvUwEu9L2EAaOCB-KAm2dp2YDK7cwscgCas4WHvNk9kh3ih8DtAutFfbXXFUgqISkwCD9UsSOgF2f5ZQvptHdRJCcHi_7CCTDaLM_UrWZA
[2020-12-01 11:55:46.362][2027594][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:150] custom-jwt: Verifying JWT token of issuer https://myissuer
[2020-12-01 11:55:46.362][2027594][debug][jwt] [source/extensions/filters/http/jwt_authn/authenticator.cc:268] custom-jwt: JWT token verification completed with: OK
[2020-12-01 11:55:46.362][2027594][debug][jwt] [source/extensions/filters/http/jwt_authn/filter.cc:109] Jwt authentication completed with: OK
[2020-12-01 11:55:46.363][2027594][info][lua] [source/extensions/filters/http/lua/lua_filter.cc:745] script log: Peer Signature: kV_FTD_BllHKImAMlqqbEm6LoHO0QYWATO5f823YckA
[2020-12-01 11:55:46.363][2027594][info][lua] [source/extensions/filters/http/lua/lua_filter.cc:745] script log: JWT Signature: kV_FTD_BllHKImAMlqqbEm6LoHO0QYWATO5f823YckA
[2020-12-01 11:55:46.363][2027594][info][lua] [source/extensions/filters/http/lua/lua_filter.cc:745] script log: Sec-Token-Binding Header Ag4AAAEGAQDBSPWUJNCy9HRx97zSWZJapZBrzfmiBvFs2NytWkg3DqOYek8TwyYoJ1GWYgfJ0ywMLyt8-qjTUMz9oSazPVazp0clqrQv8Ojgh99KR5J8ZKYKB-0EV8X1xSfJGBTz_kEU_Amseb_V5xG-VKfjczk0MaZiWpwrMZ8rogvgvvtGBFTnn_h7YTZxouYRf89PQ-HdQ7hoblcepPD1wBZ-nVmTW8eI6lbm5PiZQlylxROE_lcLPtTTKrIrOwSEgZ6iNpHnl2rwgP8Mu3RFrKQI9X74zw8ZKmbaZCfI4GaZcEaim8RIJlkhNFkdl8uNvs_ItpGeF15Esc4dbeWycfJnzdA5AwEAAQEAiO95gLlauIdYDQ1N647ELVnI-gykzW7oWC0U5IUMlJo-xbLouIv1AsTc4n8CaERUzZ1ezdXGMY-E3FBeJ1uxlF5UtCzjoRdvduMgpXJYryaJrZqCYbd5zR5JWKDaZxWFjSam7CtDqCKvyLEkXNcu4tL_rEZUFIsb3M-zJGMSuhp3NdfEwjbXNgXYDAf7frgrF1wrLA9E2oFfbz41EO3_Yu8i_ZGElsnhxogHi-GJcUoCAz79h7JFUo5q_cUcBsor_Gl8IwTLwcd85Xxdow2soUOqZ1qoP07J62cX7-LlZmDk0EpY9FmtUEO06eQ_nMMKWqxDQhR3SsEgw-Z1otVtTQAA
[2020-12-01 11:55:46.363][2027594][info][lua] [source/extensions/filters/http/lua/lua_filter.cc:745] script log: urlEncodedPemEncodedPeerCertificate -----BEGIN%20CERTIFICATE-----%0AMIIEIDCCAwigAwIBAgIBEjANBgkqhkiG9w0BAQUFADBXMQswCQYDVQQGEwJVUzEP%0AMA0GA1UECgwGR29vZ2xlMRMwEQYDVQQLDApFbnRlcnByaXNlMSIwIAYDVQQDDBlF%0AbnRlcnByaXNlIFN1Ym9yZGluYXRlIENBMB4XDTIwMTEyODE0MDgzMloXDTIyMTEy%0AODE0MDgzMlowTDELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkdvb2dsZTETMBEGA1UE%0ACwwKRW50ZXJwcmlzZTEXMBUGA1UEAwwOc3RzLmRvbWFpbi5jb20wggEiMA0GCSqG%0ASIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBSPWUJNCy9HRx97zSWZJapZBrzfmiBvFs%0A2NytWkg3DqOYek8TwyYoJ1GWYgfJ0ywMLyt8%2BqjTUMz9oSazPVazp0clqrQv8Ojg%0Ah99KR5J8ZKYKB%2B0EV8X1xSfJGBTz%2FkEU%2FAmseb%2FV5xG%2BVKfjczk0MaZiWpwrMZ8r%0AogvgvvtGBFTnn%2Fh7YTZxouYRf89PQ%2BHdQ7hoblcepPD1wBZ%2BnVmTW8eI6lbm5PiZ%0AQlylxROE%2FlcLPtTTKrIrOwSEgZ6iNpHnl2rwgP8Mu3RFrKQI9X74zw8ZKmbaZCfI%0A4GaZcEaim8RIJlkhNFkdl8uNvs%2FItpGeF15Esc4dbeWycfJnzdA5AgMBAAGjggEA%0AMIH9MA4GA1UdDwEB%2FwQEAwIHgDAJBgNVHRMEAjAAMB0GA1UdDgQWBBTmvFiUC6k7%0ALLYQ2dQuyAL56JMJ2DAfBgNVHSMEGDAWgBS%2F4RzwIkiP%2FDvPXdntrohwId%2FdhjBE%0ABggrBgEFBQcBAQQ4MDYwNAYIKwYBBQUHMAKGKGh0dHA6Ly9wa2kuZXNvZGVtb2Fw%0AcDIuY29tL2NhL3Rscy1jYS5jZXIwOQYDVR0fBDIwMDAuoCygKoYoaHR0cDovL3Br%0AaS5lc29kZW1vYXBwMi5jb20vY2EvdGxzLWNhLmNybDAfBgNVHREEGDAWghRjbGll%0AbnRqd3QuZG9tYWluLmNvbTANBgkqhkiG9w0BAQUFAAOCAQEAxb1jWdcXGAKwiMRV%0AISph57w%2BWQjiu6B%2FCMI1ven1qu5a3a5Su0GoloOdIhr8qpi8X5dZL8qKjvDvy%2FZY%0AqeJoZ72cgj4ewgX0m5Cd7jt9R01IDx%2BUfvHg%2FZhwabMD%2BlBXjSpZJHl9gFa%2BUQ%2Ba%0AfcQT%2F2UYYHT6gUe%2Bc2DP2Zph7AJoABi2eOtupSN45xKaoLGNupMRGAsm1U4Wa7vP%0Ac3770srgPczH1FMiq3HObF%2FqzKjgKVa7T4iQ%2ByU%2BIOKX%2B9lP3wRR2x5ujF7uGNGd%0Ac8weuF4aVSU39TtzVTZLliqs5qnndu4tsUpzUA55gZ26p5uSk9MOn1C%2FfWnSMzpy%0A%2FKCKfg%3D%3D%0A-----END%20CERTIFICATE-----%0A
[2020-12-01 11:55:46.363][2027594][debug][lua] [source/extensions/filters/common/lua/lua.cc:39] coroutine finished
[2020-12-01 11:55:46.363][2027594][debug][router] [source/common/router/router.cc:424] [C1][S11931256139829432601] cluster 'service_httpbin' match for URL '/get'
[2020-12-01 11:55:46.363][2027594][debug][router] [source/common/router/router.cc:581] [C1][S11931256139829432601] router decoding headers:
':authority', 'http.domain.com'
':path', '/get'
':method', 'GET'
':scheme', 'http'
'user-agent', 'curl/7.72.0'
'accept', '*/*'
'sec-token-binding', 'Ag4AAAEGAQDBSPWUJNCy9HRx97zSWZJapZBrzfmiBvFs2NytWkg3DqOYek8TwyYoJ1GWYgfJ0ywMLyt8-qjTUMz9oSazPVazp0clqrQv8Ojgh99KR5J8ZKYKB-0EV8X1xSfJGBTz_kEU_Amseb_V5xG-VKfjczk0MaZiWpwrMZ8rogvgvvtGBFTnn_h7YTZxouYRf89PQ-HdQ7hoblcepPD1wBZ-nVmTW8eI6lbm5PiZQlylxROE_lcLPtTTKrIrOwSEgZ6iNpHnl2rwgP8Mu3RFrKQI9X74zw8ZKmbaZCfI4GaZcEaim8RIJlkhNFkdl8uNvs_ItpGeF15Esc4dbeWycfJnzdA5AwEAAQEAiO95gLlauIdYDQ1N647ELVnI-gykzW7oWC0U5IUMlJo-xbLouIv1AsTc4n8CaERUzZ1ezdXGMY-E3FBeJ1uxlF5UtCzjoRdvduMgpXJYryaJrZqCYbd5zR5JWKDaZxWFjSam7CtDqCKvyLEkXNcu4tL_rEZUFIsb3M-zJGMSuhp3NdfEwjbXNgXYDAf7frgrF1wrLA9E2oFfbz41EO3_Yu8i_ZGElsnhxogHi-GJcUoCAz79h7JFUo5q_cUcBsor_Gl8IwTLwcd85Xxdow2soUOqZ1qoP07J62cX7-LlZmDk0EpY9FmtUEO06eQ_nMMKWqxDQhR3SsEgw-Z1otVtTQAA'
'x-forwarded-proto', 'https'
'x-request-id', '6b055eea-7fde-4a21-aa98-dcdd0d520ef7'
'x-envoy-expected-rq-timeout-ms', '15000'

[2020-12-01 11:55:46.363][2027594][debug][pool] [source/common/http/conn_pool_base.cc:79] queueing stream due to no available connections
[2020-12-01 11:55:46.363][2027594][debug][pool] [source/common/conn_pool/conn_pool_base.cc:105] creating a new connection
[2020-12-01 11:55:46.363][2027594][debug][client] [source/common/http/codec_client.cc:39] [C2] connecting
[2020-12-01 11:55:46.363][2027594][debug][connection] [source/common/network/connection_impl.cc:813] [C2] connecting to 3.230.36.204:80
[2020-12-01 11:55:46.363][2027594][debug][connection] [source/common/network/connection_impl.cc:829] [C2] connection in progress
[2020-12-01 11:55:46.378][2027594][debug][connection] [source/common/network/connection_impl.cc:635] [C2] connected
[2020-12-01 11:55:46.378][2027594][debug][client] [source/common/http/codec_client.cc:77] [C2] connected
[2020-12-01 11:55:46.378][2027594][debug][pool] [source/common/conn_pool/conn_pool_base.cc:220] [C2] attaching to next stream
[2020-12-01 11:55:46.378][2027594][debug][pool] [source/common/conn_pool/conn_pool_base.cc:129] [C2] creating stream
[2020-12-01 11:55:46.379][2027594][debug][router] [source/common/router/upstream_request.cc:354] [C1][S11931256139829432601] pool ready
[2020-12-01 11:55:46.382][2027582][debug][main] [source/server/server.cc:196] flushing stats
[2020-12-01 11:55:46.394][2027594][debug][router] [source/common/router/router.cc:1172] [C1][S11931256139829432601] upstream headers complete: end_stream=false
[2020-12-01 11:55:46.394][2027594][debug][http] [source/common/http/conn_manager_impl.cc:1493] [C1][S11931256139829432601] encoding headers via codec (end_stream=false):
':status', '200'
'date', 'Tue, 01 Dec 2020 16:55:46 GMT'
'content-type', 'application/json'
'content-length', '1071'
'server', 'envoy'
'access-control-allow-origin', '*'
'access-control-allow-credentials', 'true'
'x-envoy-upstream-service-time', '30'

[2020-12-01 11:55:46.394][2027594][debug][client] [source/common/http/codec_client.cc:109] [C2] response complete
```

### Conclustion

That it...well, until the upstream envoy bug is fixed.  After that, i'll edit the wasm example to actually extract and validate the `Sec-Token-Binding` heaer with the token and TLS context.
