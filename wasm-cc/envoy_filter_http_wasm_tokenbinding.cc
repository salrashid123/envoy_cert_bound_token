
#include <string>

#include <string_view>
#include <unordered_map>

#include "base64/base64.h"

#include "proxy_wasm_intrinsics.h"
#include "proxy_wasm_intrinsics_lite.pb.h"

#include "google/protobuf/util/json_util.h"
#include "examples/wasm-cc/tokenbound/tokenbound.pb.h"


using google::protobuf::util::JsonParseOptions;
using tokenbound::Config;


class TokenBindingRootContext : public RootContext {
public:
  explicit TokenBindingRootContext(uint32_t id, std::string_view root_id) : RootContext(id, root_id) {}
  bool onStart(size_t) override;
  bool onConfigure(size_t) override;
  void onTick() override;

  tokenbound::Config config_;
};



class TokenBindingContext : public Context {
public:
  explicit TokenBindingContext(uint32_t id, RootContext* root) : Context(id, root), root_(static_cast<TokenBindingRootContext*>(static_cast<void*>(root))) {}

  void onCreate() override;
  FilterHeadersStatus onRequestHeaders(uint32_t headers, bool end_of_stream) override;
  FilterDataStatus onRequestBody(size_t body_buffer_length, bool end_of_stream) override;
  FilterHeadersStatus onResponseHeaders(uint32_t headers, bool end_of_stream) override;
  FilterDataStatus onResponseBody(size_t body_buffer_length, bool end_of_stream) override;

  void onDone() override;
  void onLog() override;
  void onDelete() override;

private:
  TokenBindingRootContext* root_;
};


static RegisterContextFactory register_TokenBindingContext(CONTEXT_FACTORY(TokenBindingContext),
                                                      ROOT_FACTORY(TokenBindingRootContext),
                                                      "tb_root_id");

bool TokenBindingRootContext::onStart(size_t) {
  LOG_TRACE("onStart");
  return true;
}

bool TokenBindingRootContext::onConfigure(size_t config_size) {
  LOG_TRACE("onConfigure");
  proxy_set_tick_period_milliseconds(1000); // 1 sec

  const WasmDataPtr configuration = getBufferBytes(WasmBufferType::PluginConfiguration, 0, config_size);

    JsonParseOptions json_options;
    if (!JsonStringToMessage(
        configuration->toString(),
        &config_,
        json_options).ok()) {
      LOG_WARN("Cannot parse plugin configuration JSON string: " + configuration->toString());
      return false;
    }
    LOG_DEBUG("TokenBinding Configured for filter " + config_.jwtfiltername());
  return true;
}

void TokenBindingRootContext::onTick() { LOG_TRACE("onTick"); }

void TokenBindingContext::onCreate() { LOG_WARN(std::string("onCreate " + std::to_string(id()))); }

FilterHeadersStatus TokenBindingContext::onRequestHeaders(uint32_t, bool) {
  LOG_DEBUG(std::string("onRequestHeaders ") + std::to_string(id()));
  auto result = getRequestHeaderPairs();
  auto pairs = result->pairs();
  LOG_DEBUG(std::string("headers: ") + std::to_string(pairs.size()));
  for (auto& p : pairs) {
    LOG_DEBUG(std::string(p.first) + std::string(" -> ") + std::string(p.second));
  }

  std::string digest_from_cbf_header;
  if (!getValue({"metadata", "filter_metadata", "envoy.filters.http.jwt_authn", root_->config_.jwtfiltername(), "cbf", "x5t#S256"}, &digest_from_cbf_header)) {
    LOG_ERROR("No jwt_payload metadata present");
    closeRequest();
  }
  LOG_DEBUG(std::string(" x5t#S256 -> ") + digest_from_cbf_header);

  std::string peer_cert;
  if (!getValue({"connection", "subject_peer_certificate"}, &peer_cert)) {
    LOG_ERROR("missing subject_peer_certificate value");
    closeRequest();
  }
  LOG_DEBUG(std::string(" subject_peer_certificate: ") + peer_cert);


  std::string sha256_peer_certificate_digest;
  if (!getValue({"connection", "sha256_peer_certificate_digest"}, &sha256_peer_certificate_digest)) {
    LOG_ERROR("missing sha256_peer_certificate_digest value");
    closeRequest();
  }

  std::string encoded_digest = base64_encode(hex2bin(sha256_peer_certificate_digest));

  LOG_DEBUG(std::string("sha256_peer_certificate_digest: ") + encoded_digest);

  if (encoded_digest.compare(digest_from_cbf_header) != 0) {
    LOG_ERROR("sha256_peer_certificate_digest does not match digest_from_cbf_header");
    // TODO: send sendLocalResponse...the close just rudely terminates...
    closeRequest();
  }
   LOG_DEBUG(std::string("sha256_peer_certificate_digest and digest_from_cbf_header matched"));
  
  return FilterHeadersStatus::Continue;
}

FilterHeadersStatus TokenBindingContext::onResponseHeaders(uint32_t, bool) {
  LOG_DEBUG(std::string("onResponseHeaders ") + std::to_string(id()));
  auto result = getResponseHeaderPairs();
  auto pairs = result->pairs();
  LOG_DEBUG(std::string("headers: ") + std::to_string(pairs.size()));
  for (auto& p : pairs) {
    LOG_DEBUG(std::string(p.first) + std::string(" -> ") + std::string(p.second));
  }
  return FilterHeadersStatus::Continue;
}

FilterDataStatus TokenBindingContext::onRequestBody(size_t body_buffer_length,
                                               bool /* end_of_stream */) {
  auto body = getBufferBytes(WasmBufferType::HttpRequestBody, 0, body_buffer_length);
  LOG_DEBUG(std::string("onRequestBody ") + std::string(body->view()));
  return FilterDataStatus::Continue;
}

FilterDataStatus TokenBindingContext::onResponseBody(size_t /* body_buffer_length */,
                                                bool /* end_of_stream */) {
  return FilterDataStatus::Continue;
}

void TokenBindingContext::onDone() { LOG_WARN(std::string("onDone " + std::to_string(id()))); }

void TokenBindingContext::onLog() { LOG_WARN(std::string("onLog " + std::to_string(id()))); }

void TokenBindingContext::onDelete() { LOG_WARN(std::string("onDelete " + std::to_string(id()))); }


