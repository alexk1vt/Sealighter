#pragma once
#include "sealighter_krabs.h"
#include "sealighter_json.h"

//for gRPC
#include <iostream>
#include <memory>
#include <string>
#include <thread>

#include <grpc/support/log.h>
#include <grpcpp/grpcpp.h>

#include "../proto/string_example.grpc.pb.h"

using grpc::Channel;
using grpc::ClientAsyncResponseReader;
using grpc::ClientContext;
using grpc::CompletionQueue;
using grpc::Status;
using stringexample::Sender;
using stringexample::SendResponse;
using stringexample::EventString;

struct event_buffer_t {
    event_buffer_t()
    {}

    json json_event;
};


struct event_buffer_list_t {
    event_buffer_list_t
    (
        std::uint32_t id,
        std::uint32_t max
    )
        : event_id(id)
        , max_before_buffering(max)
        , event_count(0)
    {}

    const std::uint32_t event_id;
    const std::uint32_t max_before_buffering;

    std::uint32_t event_count;
    std::vector<std::string> properties_to_compare;
    std::vector<json> json_event_buffered;
};

struct sealighter_context_t {
    sealighter_context_t
    (
        std::string name,
        bool dump_event
    )
        : trace_name(name)
        , dump_raw_event(dump_event)
    {}

    const std::string trace_name;
    const bool dump_raw_event;
};

/*
    Parse incoming events into JSON and output
*/
void handle_event
(
    const EVENT_RECORD&     record,
    const trace_context&    trace_context
);

/*
    Parse incoming events into JSON and output
*/
void handle_event_context
(
    const EVENT_RECORD& record,
    const trace_context& trace_context,
    std::shared_ptr<struct sealighter_context_t> event_context
);

/*
    Hold whether we should be outputting the parsed JSON event
*/
enum Output_format
{
    output_stdout,
    output_event_log,
    output_file,
    output_rpc
};

/*
    Log an event to stdout, file, or Event log
*/
void log_event
(
    std::string    event_string
);


/*
    Create stream to write to output file
*/
int setup_logger_file
(
    std::string filename
);

/*
    Close stream to output file
*/
void teardown_logger_file();

/*
    Create stream to write to rpc
*/
void setup_logger_rpc
(
    std::string rpc_target
);

/*
     Close stream to rpc
*/
void teardown_logger_rpc();

/*
    Stores the global output format
*/
void set_output_format
(
    Output_format format
);

void add_buffered_list
(
    std::string trace_name,
    event_buffer_list_t buffered_list
);

void set_buffer_lists_timeout
(
    uint32_t timeout
);

void start_bufferring();

void stop_bufferring();

//gRPC class
class SenderClient {
public:
    explicit SenderClient(std::shared_ptr<Channel> channel)
        : stub_(Sender::NewStub(channel)) {}

    // Assembles the client's payload and sends it to the server.
    void SendString(const std::string& event_string) {
        // Data we are sending to the server.
        EventString package;
        package.set_data(event_string);

        // Call object to store rpc data
        AsyncClientCall* call = new AsyncClientCall;

        // stub_->PrepareAsyncSayHello() creates an RPC object, returning
        // an instance to store in "call" but does not actually start the RPC
        // Because we are using the asynchronous API, we need to hold on to
        // the "call" instance in order to get updates on the ongoing RPC.
        call->response_reader =
            stub_->PrepareAsyncSendString(&call->context, package, &cq_);

        // StartCall initiates the RPC call
        call->response_reader->StartCall();

        // Request that, upon completion of the RPC, "reply" be updated with the
        // server's response; "status" with the indication of whether the operation
        // was successful. Tag the request with the memory address of the call
        // object.
        call->response_reader->Finish(&call->reply, &call->status, (void*)call);
    }

    // Loop while listening for completed responses.
    // Prints out the response from the server.
    void AsyncCompleteRpc
    () {
        void* got_tag;
        bool ok = false;

        // Block until the next result is available in the completion queue "cq".
        while (cq_.Next(&got_tag, &ok) && thread_live) {
            // The tag in this example is the memory location of the call object
            AsyncClientCall* call = static_cast<AsyncClientCall*>(got_tag);

            // Verify that the request was completed successfully. Note that "ok"
            // corresponds solely to the request for updates introduced by Finish().
            GPR_ASSERT(ok);

            /*if (call->status.ok())
                std::cout << "Server responded: " << call->reply.message() << std::endl
            else
                std::cout << "RPC failed" << std::endl;*/

            if (!call->status.ok())
                std::cout << "RPC failed" << std::endl;

            // Once we're complete, deallocate the call object.
            delete call;
        }
    }

    void setThreadStatus(bool status) {
        thread_live = status;
    }

    std::thread thread_; //address of thread

private:
    // struct for keeping state and data information
    struct AsyncClientCall {
        // Container for the data we expect from the server.
        SendResponse reply;

        // Context for the client. It could be used to convey extra information to
        // the server and/or tweak certain RPC behaviors.
        ClientContext context;

        // Storage for the status of the RPC upon completion.
        Status status;

        std::unique_ptr<ClientAsyncResponseReader<SendResponse>> response_reader;
    };

    // Out of the passed in Channel comes the stub, stored here, our view of the
    // server's exposed services.
    std::unique_ptr<Sender::Stub> stub_;

    // The producer-consumer queue we use to communicate asynchronously with the
    // gRPC runtime.
    CompletionQueue cq_;
    
    bool thread_live; // indicate whether to terminate thread
};