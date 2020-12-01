// NOLINT(namespace-envoy)
#include <string>
#include <string_view>
#include <unordered_map>

#include "proxy_wasm_intrinsics.h"
#include "proxy_wasm_intrinsics_lite.pb.h"

#include "common/common/base64.h"

#include "google/protobuf/util/json_util.h"
#include "examples/wasm-cc/tokenbound/tokenbound.pb.h"

using google::protobuf::util::JsonParseOptions;
using google::protobuf::util::error::Code;
using google::protobuf::util::Status;

using tokenbound::Config;

class ExampleRootContext : public RootContext {
public:
  explicit ExampleRootContext(uint32_t id, std::string_view root_id) : RootContext(id, root_id) {}
  bool onStart(size_t) override;
  bool onConfigure(size_t) override;
  void onTick() override;

  tokenbound::Config config_;
};

class ExampleContext : public Context {
public:
  explicit ExampleContext(uint32_t id, RootContext* root) : Context(id, root), root_(static_cast<ExampleRootContext*>(static_cast<void*>(root))) {}

  void onCreate() override;
  FilterHeadersStatus onRequestHeaders(uint32_t headers, bool end_of_stream) override;
  FilterDataStatus onRequestBody(size_t body_buffer_length, bool end_of_stream) override;
  FilterHeadersStatus onResponseHeaders(uint32_t headers, bool end_of_stream) override;
  FilterDataStatus onResponseBody(size_t body_buffer_length, bool end_of_stream) override;

  void onDone() override;
  void onLog() override;
  void onDelete() override;

private:
  ExampleRootContext* root_;
};
static RegisterContextFactory register_ExampleContext(CONTEXT_FACTORY(ExampleContext),
                                                      ROOT_FACTORY(ExampleRootContext),
                                                      "my_root_id");

bool ExampleRootContext::onStart(size_t) {
  LOG_TRACE("onStart");
  return true;
}

bool ExampleRootContext::onConfigure(size_t config_size) {
  LOG_TRACE("onConfigure");
  proxy_set_tick_period_milliseconds(1000); // 1 sec

  const WasmDataPtr configuration = getBufferBytes(WasmBufferType::PluginConfiguration, 0, config_size);

    JsonParseOptions json_options;
    const Status options_status = JsonStringToMessage(
        configuration->toString(),
        &config_,
        json_options);
    if (options_status != Status::OK) {
      LOG_WARN("Cannot parse plugin configuration JSON string: " + configuration->toString());
      return false;
    }
    LOG_DEBUG("JWT filter payload Name: " + config_.jwtfiltername());
  return true;
}

void ExampleRootContext::onTick() { LOG_TRACE("onTick"); }

void ExampleContext::onCreate() { LOG_WARN(std::string("onCreate " + std::to_string(id()))); }

FilterHeadersStatus ExampleContext::onRequestHeaders(uint32_t, bool) {
  LOG_DEBUG(std::string("onRequestHeaders ") + std::to_string(id()));
  auto result = getRequestHeaderPairs();
  auto pairs = result->pairs();
  LOG_DEBUG(std::string("headers: ") + std::to_string(pairs.size()));
  for (auto& p : pairs) {
    LOG_DEBUG(std::string(p.first) + std::string(" -> ") + std::string(p.second));
  }

  std::string value;
  if (!getValue({"metadata", "filter_metadata", "envoy.filters.http.jwt_authn", root_->config_.jwtfiltername(), "cbf", "x5t#S256"}, &value)) {
    LOG_ERROR("No jwt_payload metadata present");
    closeRequest();
  }
  LOG_INFO(std::string(" x5t#S256 -> ") + value);

  std::string peer_cert;
  if (!getValue({"connection", "subject_peer_certificate"}, &peer_cert)) {
    LOG_ERROR("missing subject_peer_certificate value");
    closeRequest();
  }
  LOG_INFO(std::string(" subject_peer_certificate -> ") + peer_cert);


  //std::string data = Envoy::Base64::encode(fingerprint_string,strlen(fingerprint_string),false);
  
  auto secTokenBinding = getRequestHeader("Sec-Token-Binding");
  LOG_INFO(std::string("Sec-Token-Binding Header ") + std::string(secTokenBinding->view()));

  return FilterHeadersStatus::Continue;
}

FilterHeadersStatus ExampleContext::onResponseHeaders(uint32_t, bool) {
  LOG_DEBUG(std::string("onResponseHeaders ") + std::to_string(id()));
  auto result = getResponseHeaderPairs();
  auto pairs = result->pairs();
  LOG_DEBUG(std::string("headers: ") + std::to_string(pairs.size()));
  for (auto& p : pairs) {
    LOG_DEBUG(std::string(p.first) + std::string(" -> ") + std::string(p.second));
  }
  return FilterHeadersStatus::Continue;
}

FilterDataStatus ExampleContext::onRequestBody(size_t body_buffer_length,
                                               bool /* end_of_stream */) {
  auto body = getBufferBytes(WasmBufferType::HttpRequestBody, 0, body_buffer_length);
  LOG_DEBUG(std::string("onRequestBody ") + std::string(body->view()));
  return FilterDataStatus::Continue;
}

FilterDataStatus ExampleContext::onResponseBody(size_t /* body_buffer_length */,
                                                bool /* end_of_stream */) {
  return FilterDataStatus::Continue;
}

void ExampleContext::onDone() { LOG_WARN(std::string("onDone " + std::to_string(id()))); }

void ExampleContext::onLog() { LOG_WARN(std::string("onLog " + std::to_string(id()))); }

void ExampleContext::onDelete() { LOG_WARN(std::string("onDelete " + std::to_string(id()))); }
