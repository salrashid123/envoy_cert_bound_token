load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

proto_library(
    name = "tokenbound_proto",
    srcs = ["tokenbound.proto"],
    visibility = ["//visibility:public"],
)

cc_proto_library(
    name = "tokenbound_cc_proto",
    deps = [
        ":tokenbound_proto",
    ],
    visibility = ["//visibility:public"],
)
