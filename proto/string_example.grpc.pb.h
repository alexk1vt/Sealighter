// Generated by the gRPC C++ plugin.
// If you make any local change, they will be lost.
// source: string_example.proto
// Original file comments:
// Copyright 2015 gRPC authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#ifndef GRPC_string_5fexample_2eproto__INCLUDED
#define GRPC_string_5fexample_2eproto__INCLUDED

#include "string_example.pb.h"

#include <functional>
#include <grpcpp/generic/async_generic_service.h>
#include <grpcpp/support/async_stream.h>
#include <grpcpp/support/async_unary_call.h>
#include <grpcpp/impl/codegen/client_callback.h>
#include <grpcpp/impl/codegen/client_context.h>
#include <grpcpp/impl/codegen/completion_queue.h>
#include <grpcpp/impl/codegen/message_allocator.h>
#include <grpcpp/impl/codegen/method_handler.h>
#include <grpcpp/impl/codegen/proto_utils.h>
#include <grpcpp/impl/codegen/rpc_method.h>
#include <grpcpp/impl/codegen/server_callback.h>
#include <grpcpp/impl/codegen/server_callback_handlers.h>
#include <grpcpp/impl/codegen/server_context.h>
#include <grpcpp/impl/codegen/service_type.h>
#include <grpcpp/impl/codegen/status.h>
#include <grpcpp/impl/codegen/stub_options.h>
#include <grpcpp/impl/codegen/sync_stream.h>

namespace stringexample {

// The greeting service definition.
class Sender final {
 public:
  static constexpr char const* service_full_name() {
    return "stringexample.Sender";
  }
  class StubInterface {
   public:
    virtual ~StubInterface() {}
    // Sends a string
    virtual ::grpc::Status SendString(::grpc::ClientContext* context, const ::stringexample::EventString& request, ::stringexample::SendResponse* response) = 0;
    std::unique_ptr< ::grpc::ClientAsyncResponseReaderInterface< ::stringexample::SendResponse>> AsyncSendString(::grpc::ClientContext* context, const ::stringexample::EventString& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncResponseReaderInterface< ::stringexample::SendResponse>>(AsyncSendStringRaw(context, request, cq));
    }
    std::unique_ptr< ::grpc::ClientAsyncResponseReaderInterface< ::stringexample::SendResponse>> PrepareAsyncSendString(::grpc::ClientContext* context, const ::stringexample::EventString& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncResponseReaderInterface< ::stringexample::SendResponse>>(PrepareAsyncSendStringRaw(context, request, cq));
    }
    class async_interface {
     public:
      virtual ~async_interface() {}
      // Sends a string
      virtual void SendString(::grpc::ClientContext* context, const ::stringexample::EventString* request, ::stringexample::SendResponse* response, std::function<void(::grpc::Status)>) = 0;
      virtual void SendString(::grpc::ClientContext* context, const ::stringexample::EventString* request, ::stringexample::SendResponse* response, ::grpc::ClientUnaryReactor* reactor) = 0;
    };
    typedef class async_interface experimental_async_interface;
    virtual class async_interface* async() { return nullptr; }
    class async_interface* experimental_async() { return async(); }
   private:
    virtual ::grpc::ClientAsyncResponseReaderInterface< ::stringexample::SendResponse>* AsyncSendStringRaw(::grpc::ClientContext* context, const ::stringexample::EventString& request, ::grpc::CompletionQueue* cq) = 0;
    virtual ::grpc::ClientAsyncResponseReaderInterface< ::stringexample::SendResponse>* PrepareAsyncSendStringRaw(::grpc::ClientContext* context, const ::stringexample::EventString& request, ::grpc::CompletionQueue* cq) = 0;
  };
  class Stub final : public StubInterface {
   public:
    Stub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options = ::grpc::StubOptions());
    ::grpc::Status SendString(::grpc::ClientContext* context, const ::stringexample::EventString& request, ::stringexample::SendResponse* response) override;
    std::unique_ptr< ::grpc::ClientAsyncResponseReader< ::stringexample::SendResponse>> AsyncSendString(::grpc::ClientContext* context, const ::stringexample::EventString& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncResponseReader< ::stringexample::SendResponse>>(AsyncSendStringRaw(context, request, cq));
    }
    std::unique_ptr< ::grpc::ClientAsyncResponseReader< ::stringexample::SendResponse>> PrepareAsyncSendString(::grpc::ClientContext* context, const ::stringexample::EventString& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncResponseReader< ::stringexample::SendResponse>>(PrepareAsyncSendStringRaw(context, request, cq));
    }
    class async final :
      public StubInterface::async_interface {
     public:
      void SendString(::grpc::ClientContext* context, const ::stringexample::EventString* request, ::stringexample::SendResponse* response, std::function<void(::grpc::Status)>) override;
      void SendString(::grpc::ClientContext* context, const ::stringexample::EventString* request, ::stringexample::SendResponse* response, ::grpc::ClientUnaryReactor* reactor) override;
     private:
      friend class Stub;
      explicit async(Stub* stub): stub_(stub) { }
      Stub* stub() { return stub_; }
      Stub* stub_;
    };
    class async* async() override { return &async_stub_; }

   private:
    std::shared_ptr< ::grpc::ChannelInterface> channel_;
    class async async_stub_{this};
    ::grpc::ClientAsyncResponseReader< ::stringexample::SendResponse>* AsyncSendStringRaw(::grpc::ClientContext* context, const ::stringexample::EventString& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientAsyncResponseReader< ::stringexample::SendResponse>* PrepareAsyncSendStringRaw(::grpc::ClientContext* context, const ::stringexample::EventString& request, ::grpc::CompletionQueue* cq) override;
    const ::grpc::internal::RpcMethod rpcmethod_SendString_;
  };
  static std::unique_ptr<Stub> NewStub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options = ::grpc::StubOptions());

  class Service : public ::grpc::Service {
   public:
    Service();
    virtual ~Service();
    // Sends a string
    virtual ::grpc::Status SendString(::grpc::ServerContext* context, const ::stringexample::EventString* request, ::stringexample::SendResponse* response);
  };
  template <class BaseClass>
  class WithAsyncMethod_SendString : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithAsyncMethod_SendString() {
      ::grpc::Service::MarkMethodAsync(0);
    }
    ~WithAsyncMethod_SendString() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status SendString(::grpc::ServerContext* /*context*/, const ::stringexample::EventString* /*request*/, ::stringexample::SendResponse* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    void RequestSendString(::grpc::ServerContext* context, ::stringexample::EventString* request, ::grpc::ServerAsyncResponseWriter< ::stringexample::SendResponse>* response, ::grpc::CompletionQueue* new_call_cq, ::grpc::ServerCompletionQueue* notification_cq, void *tag) {
      ::grpc::Service::RequestAsyncUnary(0, context, request, response, new_call_cq, notification_cq, tag);
    }
  };
  typedef WithAsyncMethod_SendString<Service > AsyncService;
  template <class BaseClass>
  class WithCallbackMethod_SendString : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithCallbackMethod_SendString() {
      ::grpc::Service::MarkMethodCallback(0,
          new ::grpc::internal::CallbackUnaryHandler< ::stringexample::EventString, ::stringexample::SendResponse>(
            [this](
                   ::grpc::CallbackServerContext* context, const ::stringexample::EventString* request, ::stringexample::SendResponse* response) { return this->SendString(context, request, response); }));}
    void SetMessageAllocatorFor_SendString(
        ::grpc::MessageAllocator< ::stringexample::EventString, ::stringexample::SendResponse>* allocator) {
      ::grpc::internal::MethodHandler* const handler = ::grpc::Service::GetHandler(0);
      static_cast<::grpc::internal::CallbackUnaryHandler< ::stringexample::EventString, ::stringexample::SendResponse>*>(handler)
              ->SetMessageAllocator(allocator);
    }
    ~WithCallbackMethod_SendString() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status SendString(::grpc::ServerContext* /*context*/, const ::stringexample::EventString* /*request*/, ::stringexample::SendResponse* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    virtual ::grpc::ServerUnaryReactor* SendString(
      ::grpc::CallbackServerContext* /*context*/, const ::stringexample::EventString* /*request*/, ::stringexample::SendResponse* /*response*/)  { return nullptr; }
  };
  typedef WithCallbackMethod_SendString<Service > CallbackService;
  typedef CallbackService ExperimentalCallbackService;
  template <class BaseClass>
  class WithGenericMethod_SendString : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithGenericMethod_SendString() {
      ::grpc::Service::MarkMethodGeneric(0);
    }
    ~WithGenericMethod_SendString() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status SendString(::grpc::ServerContext* /*context*/, const ::stringexample::EventString* /*request*/, ::stringexample::SendResponse* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
  };
  template <class BaseClass>
  class WithRawMethod_SendString : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithRawMethod_SendString() {
      ::grpc::Service::MarkMethodRaw(0);
    }
    ~WithRawMethod_SendString() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status SendString(::grpc::ServerContext* /*context*/, const ::stringexample::EventString* /*request*/, ::stringexample::SendResponse* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    void RequestSendString(::grpc::ServerContext* context, ::grpc::ByteBuffer* request, ::grpc::ServerAsyncResponseWriter< ::grpc::ByteBuffer>* response, ::grpc::CompletionQueue* new_call_cq, ::grpc::ServerCompletionQueue* notification_cq, void *tag) {
      ::grpc::Service::RequestAsyncUnary(0, context, request, response, new_call_cq, notification_cq, tag);
    }
  };
  template <class BaseClass>
  class WithRawCallbackMethod_SendString : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithRawCallbackMethod_SendString() {
      ::grpc::Service::MarkMethodRawCallback(0,
          new ::grpc::internal::CallbackUnaryHandler< ::grpc::ByteBuffer, ::grpc::ByteBuffer>(
            [this](
                   ::grpc::CallbackServerContext* context, const ::grpc::ByteBuffer* request, ::grpc::ByteBuffer* response) { return this->SendString(context, request, response); }));
    }
    ~WithRawCallbackMethod_SendString() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status SendString(::grpc::ServerContext* /*context*/, const ::stringexample::EventString* /*request*/, ::stringexample::SendResponse* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    virtual ::grpc::ServerUnaryReactor* SendString(
      ::grpc::CallbackServerContext* /*context*/, const ::grpc::ByteBuffer* /*request*/, ::grpc::ByteBuffer* /*response*/)  { return nullptr; }
  };
  template <class BaseClass>
  class WithStreamedUnaryMethod_SendString : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithStreamedUnaryMethod_SendString() {
      ::grpc::Service::MarkMethodStreamed(0,
        new ::grpc::internal::StreamedUnaryHandler<
          ::stringexample::EventString, ::stringexample::SendResponse>(
            [this](::grpc::ServerContext* context,
                   ::grpc::ServerUnaryStreamer<
                     ::stringexample::EventString, ::stringexample::SendResponse>* streamer) {
                       return this->StreamedSendString(context,
                         streamer);
                  }));
    }
    ~WithStreamedUnaryMethod_SendString() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable regular version of this method
    ::grpc::Status SendString(::grpc::ServerContext* /*context*/, const ::stringexample::EventString* /*request*/, ::stringexample::SendResponse* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    // replace default version of method with streamed unary
    virtual ::grpc::Status StreamedSendString(::grpc::ServerContext* context, ::grpc::ServerUnaryStreamer< ::stringexample::EventString,::stringexample::SendResponse>* server_unary_streamer) = 0;
  };
  typedef WithStreamedUnaryMethod_SendString<Service > StreamedUnaryService;
  typedef Service SplitStreamedService;
  typedef WithStreamedUnaryMethod_SendString<Service > StreamedService;
};

}  // namespace stringexample


#endif  // GRPC_string_5fexample_2eproto__INCLUDED