#include "sealighter_krabs.h"
#include "sealighter_handler.h"
#include "sealighter_errors.h"
#include "sealighter_util.h"
#include "sealighter_provider.h"

#include <fstream>
#include <mutex>
#include <atomic>

#include <TlHelp32.h> // to collect process info
#include <unordered_map> // for temp storage of process snapshot for repeated look ups

#include <locale> // for conversion from wstring to string
#include <codecvt> // for conversion from wstring to string

// -------------------------
// GLOBALS - START
// -------------------------

// Output file to write events to
static std::ofstream g_outfile;

// Helper mutex to ensure threaded functions
// print a whole event without interruption
static std::mutex g_print_mutex;

// Holds format
static Output_format g_output_format;

// Hold data for buffering
static std::map<std::string, std::vector< event_buffer_list_t>> g_buffer_lists;
// Default to 30 seconds
static std::uint32_t g_buffer_lists_timeout_seconds = 5;
static std::mutex g_buffer_lists_mutex;
static std::thread g_buffer_list_thread;
static std::atomic_bool g_buffer_thread_stop = false;
static std::condition_variable g_buffer_list_con_var;

// for gRPC
SenderClient* Sender;
unsigned int grpc_cnt;

// Indicate whether to collect ancestor process data
// Doesn't work for buffered events
static bool g_ancestor_tracking;

// holds any post-processing filters
static std::unordered_map<std::string, ppf_properties_t> g_ppf_list;

// -------------------------
// GLOBALS - END
// -------------------------
// PRIVATE FUNCTIONS - START
// -------------------------


/*
    Print a line to stdout, using a mutex
    to ensure we print each event wholey before
    another can
*/
void threaded_print_ln
(
    std::string event_string
)
{
    g_print_mutex.lock();
    log_messageA("%s\n", event_string.c_str());
    g_print_mutex.unlock();
}


/*
    Write to Event Log
*/
void write_event_log
(
    json            json_event,
    std::string     trace_name,
    std::string     event_string
)
{
    DWORD status = ERROR_SUCCESS;

    // TODO: Make sure we didn't break this
    // Also fix up schema, no need to to all the str_wstr converting
    // Also fix up timestamp string
    status = EventWriteSEALIGHTER_REPORT_EVENT(
        event_string.c_str(),
        json_event["header"]["activity_id"].get<std::string>().c_str(),
        (USHORT)json_event["header"]["event_flags"].get<std::uint32_t>(),
        (USHORT)json_event["header"]["event_id"].get<std::uint32_t>(),
        convert_str_wstr(json_event["header"]["event_name"].get<std::string>()).c_str(),
        (UCHAR)json_event["header"]["event_opcode"].get<std::uint32_t>(),
        (UCHAR)json_event["header"]["event_version"].get<std::uint32_t>(),
        json_event["header"]["process_id"].get<std::uint32_t>(),
        convert_str_wstr(json_event["header"]["provider_name"].get<std::string>()).c_str(),
        convert_str_wstr(json_event["header"]["task_name"].get<std::string>()).c_str(),
        json_event["header"]["thread_id"].get<std::uint32_t>(),
        0,  // schema.timestamp().quadPart
        trace_name.c_str()
    );

    if (status != ERROR_SUCCESS) {
        log_messageA("Error %ul line %d\n", status, __LINE__);
        return;
    }
}


/*
    Print a line to an output file, using a mutex
    to ensure we print each event wholey before
    another can
*/
void threaded_write_file_ln
(
    std::string event_string
)
{
    g_print_mutex.lock();
    g_outfile << event_string << std::endl;
    g_print_mutex.unlock();
}

/*
    Print a line to an output rpc
    Using lock to see if that prevents logjam on 60meg file output
*/
void write_rpc_ln
(
    std::string event_string
)
{
    g_print_mutex.lock();
    grpc_cnt++;
    //line to do the actual write to rpc
    Sender->SendString(event_string);
    g_print_mutex.unlock();
}

/*
    Converting wstrings to strings
    from:  https://stackoverflow.com/questions/4804298/how-to-convert-wstring-into-string
    requires:  <locale> <codecvt>
    Configured for UTF-8
*/
std::string ws2s(const std::wstring& wstr) {
    using convert_typeX = std::codecvt_utf8<wchar_t>;
    std::wstring_convert<convert_typeX, wchar_t> converterX;

    return converterX.to_bytes(wstr);
}

/*
    Get a process image file name, full path, and parent process ID
    Returns true if success, false otherwise
    Basing code off:  https://cocomelonc.github.io/pentest/2021/09/29/findmyprocess.html
    MS reference:  https://learn.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes
    MS reference:  https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32
    MS example:  https://learn.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes
*/
bool get_process_ancestors
(
    DWORD curr_pid,
    json* json_ancestors
)
{
    HANDLE snapshot_handle = NULL;
    HANDLE module_handle = NULL;
    PROCESSENTRY32 proc_entry;
    MODULEENTRY32 mod_entry;
    bool handle_result;
    std::unordered_map<DWORD, PROCESSENTRY32W> proc_map;
    std::unordered_map<DWORD, PROCESSENTRY32W>::const_iterator iter;
    std::wstring p_string;
    std::string ancestor_string;

    //std::cout << "Getting ancestor info for process: " << std::to_string(curr_pid).c_str() << std::endl;

    // initializing sizes needed for Process32First(...) and Module32First(...)
    proc_entry.dwSize = sizeof(PROCESSENTRY32);
    mod_entry.dwSize = sizeof(MODULEENTRY32);

    // collect snapshot of all running processes in the system
    snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPALL | TH32CS_SNAPMODULE32, 0); // FLAGS:  Per TlHelp32.h documentation, using SNAPALL will subsequent calls with TH32CS_SNAPMODULE flag
    if (INVALID_HANDLE_VALUE == snapshot_handle) return false;

    // get info on first process in snapshot
    
    handle_result = Process32First(snapshot_handle, &proc_entry);

    // this could take quite a lot of time if we loop through all processes every time we look up an ancestor...
    // can I iterate through list once and build a tree?  or quick hash table?
    // hash table with PID as key and PROCESSENTRY32 pointer as value?

    // populate unordered map linking PIDs to process entry pointers
    while (handle_result) {
        proc_map[proc_entry.th32ProcessID] = proc_entry;
        handle_result = Process32Next(snapshot_handle, &proc_entry);
    }

    // now loop to build json_ancestors array
    while (curr_pid > 4) { //4 is the PID of system process
        bool mod_load_status = true;
        //recall process identifyer of curr_PID
        iter = proc_map.find(curr_pid);
        if (iter == proc_map.end()) {
            break; //not able to find the PID in question in the process map so cannot proceed furtehr
        }
        proc_entry = iter->second;
    
        //get module identifier of parent process
        module_handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, curr_pid);
        // Note - parent may not be running when second snapshot is taken
        if (INVALID_HANDLE_VALUE == module_handle) {
            mod_load_status = false;
        }
        else {
            // get image file and path on first module in process
            if (!Module32First(module_handle, &mod_entry)) {
                mod_load_status = false;
            }
        }
 
        if (mod_load_status) {
            p_string.assign(mod_entry.szExePath); // get full executable path from module32first function
        }
        else {
            p_string.assign(proc_entry.szExeFile); // couldn't load module so use executable name collected during process capture
        }

        ancestor_string.assign(ws2s(p_string)); //convert wstring p_string to normal string to avoid shenanigans
        //std::cout << "Process PID: " << std::to_string(curr_pid).c_str() << " has executable: " << ancestor_string.c_str() << std::endl;

        //push parent image name and path to json array 
        json_ancestors->push_back(ancestor_string);

        //get parent PID p_pid and set as current PID
        curr_pid = proc_entry.th32ParentProcessID;
    }

    // Done.  Close handles and return
    CloseHandle(snapshot_handle);
    if (module_handle) CloseHandle(module_handle);
    if (ancestor_string.empty())
        return false;
    return true;
}

/*
    Convert an ETW Event to JSON
*/
json parse_event_to_json
(
    const EVENT_RECORD& record,
    const trace_context&,
    std::shared_ptr<struct sealighter_context_t> sealighter_context,
    krabs::schema       schema
)
{
    std::string trace_name = sealighter_context->trace_name;
    json json_properties;
    json json_properties_types;
    json json_header = {
        { "event_id", schema.event_id() },
        { "event_name", convert_wstr_str(schema.event_name()) },
        { "task_name", convert_wstr_str(schema.task_name()) },
        { "thread_id", schema.thread_id() },
        { "timestamp", convert_timestamp_string(schema.timestamp()) },
        { "event_flags", schema.event_flags() },
        { "event_opcode", schema.event_opcode() },
        { "event_version", schema.event_version() },
        { "process_id", schema.process_id()},
        { "provider_name", convert_wstr_str(schema.provider_name()) },
        { "activity_id", convert_guid_str(schema.activity_id()) },
        { "trace_name", trace_name},
    };

    json json_event = { {"header", json_header} };

    // Check if we are just dumping the raw event, or attempting to parse it
    if (sealighter_context->dump_raw_event) {
        std::string raw_hex = convert_bytearray_hexstring((BYTE*)record.UserData, record.UserDataLength);
        json_event["raw"] = raw_hex;
    }
    else {
        krabs::parser parser(schema);
        for (krabs::property& prop : parser.properties()) {
            std::wstring prop_name_wstr = prop.name();
            std::string prop_name = convert_wstr_str(prop_name_wstr);

            try
            {
                switch (prop.type())
                {
                case TDH_INTYPE_ANSISTRING:
                    json_properties[prop_name] = parser.parse<std::string>(prop_name_wstr);
                    json_properties_types[prop_name] = "STRINGA";
                    break;
                case TDH_INTYPE_UNICODESTRING:
                    json_properties[prop_name] = convert_wstr_str(parser.parse<std::wstring>(prop_name_wstr));
                    json_properties_types[prop_name] = "STRINGW";
                    break;
                case TDH_INTYPE_INT8:
                    json_properties[prop_name] = parser.parse<std::int8_t>(prop_name_wstr);
                    json_properties_types[prop_name] = "INT8";
                    break;
                case TDH_INTYPE_UINT8:
                    json_properties[prop_name] = parser.parse<std::uint8_t>(prop_name_wstr);
                    json_properties_types[prop_name] = "UINT8";
                    break;
                case TDH_INTYPE_INT16:
                    json_properties[prop_name] = parser.parse<std::int16_t>(prop_name_wstr);
                    json_properties_types[prop_name] = "INT16";
                    break;
                case TDH_INTYPE_UINT16:
                    json_properties[prop_name] = parser.parse<std::uint16_t>(prop_name_wstr);
                    json_properties_types[prop_name] = "UINT16";
                    break;
                case TDH_INTYPE_INT32:
                    json_properties[prop_name] = parser.parse<std::int32_t>(prop_name_wstr);
                    json_properties_types[prop_name] = "INT32";
                    break;
                case TDH_INTYPE_UINT32:
                    json_properties[prop_name] = parser.parse<std::uint32_t>(prop_name_wstr);
                    json_properties_types[prop_name] = "UINT32";
                    break;
                case TDH_INTYPE_INT64:
                    json_properties[prop_name] = parser.parse<std::int64_t>(prop_name_wstr);
                    json_properties_types[prop_name] = "INT64";
                    break;
                case TDH_INTYPE_UINT64:
                    json_properties[prop_name] = parser.parse<std::uint64_t>(prop_name_wstr);
                    json_properties_types[prop_name] = "UINT64";
                    break;
                case TDH_INTYPE_FLOAT:
                    json_properties[prop_name] = parser.parse<std::float_t>(prop_name_wstr);
                    json_properties_types[prop_name] = "FLOAT";
                    break;
                case TDH_INTYPE_DOUBLE:
                    json_properties[prop_name] = parser.parse<std::double_t>(prop_name_wstr);
                    json_properties_types[prop_name] = "DOUBLE";
                    break;
                case TDH_INTYPE_BOOLEAN:
                    json_properties[prop_name] = convert_bytes_bool(parser.parse<krabs::binary>(prop_name_wstr).bytes());
                    json_properties_types[prop_name] = "BOOLEAN";
                    break;
                case TDH_INTYPE_BINARY:
                    json_properties[prop_name] =
                        convert_bytevector_hexstring(parser.parse<krabs::binary>(prop_name_wstr).bytes());
                    json_properties_types[prop_name] = "BINARY";
                    break;
                case TDH_INTYPE_GUID:
                    json_properties[prop_name] =
                        convert_guid_str(parser.parse<krabs::guid>(prop_name_wstr));
                    json_properties_types[prop_name] = "GUID";
                    break;
                case TDH_INTYPE_FILETIME:
                    json_properties[prop_name] = convert_filetime_string(
                        parser.parse<FILETIME>(prop_name_wstr));
                    json_properties_types[prop_name] = "FILETIME";
                    break;
                case TDH_INTYPE_SYSTEMTIME:
                    json_properties[prop_name] = convert_systemtime_string(
                        parser.parse<SYSTEMTIME>(prop_name_wstr));
                    json_properties_types[prop_name] = "SYSTEMTIME";
                    break;
                case TDH_INTYPE_SID:
                    json_properties[prop_name] = convert_bytes_sidstring(
                        parser.parse<krabs::binary>(prop_name_wstr).bytes());
                    json_properties_types[prop_name] = "SID";
                    break;
                case TDH_INTYPE_WBEMSID:
                    // *Supposedly* like SID?
                    json_properties[prop_name] = convert_bytevector_hexstring(
                        parser.parse<krabs::binary>(prop_name_wstr).bytes());
                    json_properties_types[prop_name] = "WBEMSID";
                    break;
                case TDH_INTYPE_POINTER:
                    json_properties[prop_name] =
                        convert_ulong64_hexstring(parser.parse<krabs::pointer>(prop_name_wstr).address);
                    json_properties_types[prop_name] = "POINTER";
                    break;
                case TDH_INTYPE_HEXINT32:
                case TDH_INTYPE_HEXINT64:
                case TDH_INTYPE_MANIFEST_COUNTEDSTRING:
                case TDH_INTYPE_MANIFEST_COUNTEDANSISTRING:
                case TDH_INTYPE_RESERVED24:
                case TDH_INTYPE_MANIFEST_COUNTEDBINARY:
                case TDH_INTYPE_COUNTEDSTRING:
                case TDH_INTYPE_COUNTEDANSISTRING:
                case TDH_INTYPE_REVERSEDCOUNTEDSTRING:
                case TDH_INTYPE_REVERSEDCOUNTEDANSISTRING:
                case TDH_INTYPE_NONNULLTERMINATEDSTRING:
                case TDH_INTYPE_NONNULLTERMINATEDANSISTRING:
                case TDH_INTYPE_UNICODECHAR:
                case TDH_INTYPE_ANSICHAR:
                case TDH_INTYPE_SIZET:
                case TDH_INTYPE_HEXDUMP:
                case TDH_INTYPE_NULL:
                default:
                    json_properties[prop_name] =
                        convert_bytevector_hexstring(parser.parse<krabs::binary>(prop_name_wstr).bytes());
                    json_properties_types[prop_name] = "OTHER";
                    break;
                }
            }
            catch (...)
            {
                // Failed to parse, default to hex
                // Try hex, if something even worse is up return empty
                try
                {
                    json_properties[prop_name] =
                        convert_bytevector_hexstring(parser.parse<krabs::binary>(prop_name_wstr).bytes());
                    json_properties_types[prop_name] = "ERROR";
                }
                catch (...) {}
            }
        }
        json_event["property_types"] = json_properties_types;
        json_event["properties"] = json_properties;

        // Check if we're meant to collect process ancestor data
        // Note:  there's a chance that by the time OS is queried for process info, they are no longer running
        if (g_ancestor_tracking) {
            json json_ancestors = json::array();
            //need to get process in question PID - in the event header as process_id
            unsigned int curr_pid = schema.process_id();

            if (get_process_ancestors(curr_pid, &json_ancestors))
                json_event["process_ancestors"] = json_ancestors;
            else {
                if (!json_properties["ProcessId"].is_null()) {  // if not able to get any process ancestors from pid given in header, try pid from properties
                    if (get_process_ancestors(json_properties["ProcessId"], &json_ancestors))
                        json_event["process_ancestors"] = json_ancestors;
                }
            }



        }
    }

    // Check if we're meant to parse any extended data
    if (record.ExtendedDataCount != 0) {
        // At the moment we only support EVENT_HEADER_EXT_TYPE_STACK_TRACE64
        // The extra field is TRACE64 (and not TRACE32) even in the event the
        // process that generated the event is 32Bit
        for (USHORT i = 0; i < record.ExtendedDataCount; i++)
        {
            EVENT_HEADER_EXTENDED_DATA_ITEM data_item = record.ExtendedData[i];

            if (data_item.ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE64) {
                PEVENT_EXTENDED_ITEM_STACK_TRACE64 stacktrace =
                    (PEVENT_EXTENDED_ITEM_STACK_TRACE64)data_item.DataPtr;
                uint32_t stack_length = (data_item.DataSize - sizeof(ULONG64)) / sizeof(ULONG64);

                json json_stacktrace = json::array();
                for (size_t x = 0; x < stack_length; x++)
                {
                    // Stacktraces make more sense in hex
                    json_stacktrace.push_back(convert_ulong64_hexstring(stacktrace->Address[x]));
                }
                // We're ignoring the MatchId, which if not 0 then the stack is split across events
                // But stiching it together would be too much of a pain for the mostly-stateless
                // Sealighter. So we'll just collect what we've got.
                json_event["stack_trace"] = json_stacktrace;
            }
        }
    }

    

    return json_event;
}

void output_json_event
(
    json json_event
)
{
    // If writing to a file or RPC, don't pretty print
    // This makes it 1 line per event
    bool pretty_print = (Output_format::output_file != g_output_format) && (Output_format::output_rpc != g_output_format);
    std::string event_string = convert_json_string(json_event, pretty_print);
    std::string trace_name = json_event["header"]["trace_name"];

    // Log event if we successfully parsed it
    if (!event_string.empty()) {
        switch (g_output_format)
        {
        case output_stdout:
            threaded_print_ln(event_string);
            break;
        case output_event_log:
            write_event_log(json_event, trace_name, event_string);
            break;
        case output_file:
            threaded_write_file_ln(event_string);
            break;
        case output_rpc:
            write_rpc_ln(event_string);
            break;
        }
    }
}

void handle_event_context
(
    const EVENT_RECORD& record,
    const trace_context& trace_context,
    std::shared_ptr<struct sealighter_context_t> sealighter_context
)
{
    json json_event;
    schema schema(record, trace_context.schema_locator);
    bool buffered = false;

    std::string trace_name = sealighter_context->trace_name;
    json_event = parse_event_to_json(record, trace_context, sealighter_context, schema);

    // First check if event has post-processing filter
    if (g_ppf_list.size() > 0) { // are there any filters in the PPF list?
        if (!json_event["header"]["trace_name"].is_null()) {
            std::string trace_name = json_event["header"]["trace_name"].get<std::string>();
            if (g_ppf_list.find(trace_name) != g_ppf_list.end()) {
                // This is a trace that has a post-processing filter - check field in question for unwanted values
                auto ppf_list_elem = g_ppf_list.find(trace_name);
                std::string field_name = ppf_list_elem->second.field_name;
                std::vector<std::string> unwanted_value_vec = ppf_list_elem->second.field_values;

                if (!json_event["properties"][field_name].is_null()) {  // check to make sure we have the right field name
                    std::string event_val = json_event["properties"][field_name].get<std::string>();

                    //using std::any_of() to check for presence of any elements in unwanted_value_vec within event_val string
                    bool found = std::any_of(unwanted_value_vec.begin(), unwanted_value_vec.end(),
                        [&event_val](const auto& s) {return event_val.find(s) != std::string::npos;
                        });
                    if (found) {
                        // we don't want this event, so just ignore it
                        std::cout << "Received unwanted event; skipping\n";
                        return;
                    }
                }
                else {
                    std::cout << "Incorrect field name for this trace's PPF\n";
                }
            }
        }
    }

    // Only care about event buffering if required
    if (g_buffer_lists.size() > 0 && g_buffer_lists.find(trace_name) != g_buffer_lists.end()) {
        // Lock Mutex for safety
        g_buffer_lists_mutex.lock();

        for (event_buffer_list_t& buffer : g_buffer_lists[trace_name]) {
            if (buffer.event_id != (uint32_t)schema.event_id()) {
                continue;
            }
            if (buffer.event_count < buffer.max_before_buffering) {
                // Increment counter but report event
                buffer.event_count += 1;
                break;
            }

            // We're buffering. See if we already have the matching event
            bool matched_event = false;
            for (json& json_event_buffered : buffer.json_event_buffered) {
                bool matched_field = true;
                for (std::string prop_to_compare: buffer.properties_to_compare) {
                    auto field_event = convert_json_string(json_event["properties"][prop_to_compare], false);
                    auto field_buffered = convert_json_string(json_event_buffered["properties"][prop_to_compare], false);
                    if (field_event != field_buffered) {
                        // Not a match
                        matched_field = false;
                        break;
                    }
                }
                if (matched_field) {
                    // Matched, increase event count
                    auto old_count = json_event_buffered["header"]["buffered_count"].get<std::uint32_t>();
                    json_event_buffered["header"]["buffered_count"] = old_count + 1;
                    matched_event = true;
                }
            }
            if (!matched_event) {
                // Event wasn't in the list, add it
                json_event["header"]["buffered_count"] = 1;
                buffer.json_event_buffered.push_back(json_event);
            }
            // As we're buffering don't report event
            buffered = true;
            break;
        }
        g_buffer_lists_mutex.unlock();
    }

    // Report event only if not buffering
    if (!buffered) {
        output_json_event(json_event);
    }
}



void handle_event
(
    const EVENT_RECORD& record,
    const trace_context& trace_context
)
{
    auto dummy_context = std::make_shared<struct sealighter_context_t>("", false);
    handle_event_context(record, trace_context, dummy_context);
}

int setup_logger_file
(
    std::string filename
)
{
    g_outfile.open(filename.c_str(), std::ios::out | std::ios::app);
    if (g_outfile.good()) {
        return ERROR_SUCCESS;
    }
    else {
        return SEALIGHTER_ERROR_OUTPUT_FILE;
    }
}

void teardown_logger_file()
{
    if (g_outfile.is_open()) {
        g_outfile.close();
    }
    else if (Output_format::output_rpc == g_output_format) {
        std::cout << "Reported " << grpc_cnt << " RPC events\n";
        std::cout << "Tearing down RPC\n";
        teardown_logger_rpc();
    }
}

// Receives string containing config to access server channel.  Ex:
// to reach localhost at port 50051, string is ""localhost:50051"
void setup_logger_rpc
(
    std::string rpc_target
)
{
    grpc_cnt = 0;
    std::cout << "Sending events via gRPC to: " << rpc_target << std::endl;
    Sender = new SenderClient(grpc::CreateChannel(rpc_target.c_str(),
        grpc::InsecureChannelCredentials()));

    // Spawn reader thread that loops indefinitely
    Sender->setThreadStatus(true);
    Sender->thread_ = std::thread(&SenderClient::AsyncCompleteRpc, Sender);

    return;
}

void teardown_logger_rpc()
{
    Sender->setThreadStatus(false); // notifies gRPC thread to terminate
    Sender->thread_.join(); // waits for child thread to terminate
    return;
}

void set_output_format(Output_format format)
{
    g_output_format = format;
}

void set_ancestor_tracking(bool set)
{
    g_ancestor_tracking = set;
}

void add_buffered_list
(
    std::string trace_name,
    event_buffer_list_t buffered_list
)
{
    if (g_buffer_lists.find(trace_name) == g_buffer_lists.end()) {
        g_buffer_lists[trace_name] = std::vector<event_buffer_list_t>();
    }
    g_buffer_lists[trace_name].push_back(buffered_list);
}

void set_buffer_lists_timeout
(
    uint32_t timeout
)
{
    g_buffer_lists_timeout_seconds = timeout;
}

void flush_buffered_lists()
{
    g_buffer_lists_mutex.lock();
    for (auto& buffer_list : g_buffer_lists) {
        for (auto& buffer : buffer_list.second) {
            for (auto& json_event : buffer.json_event_buffered) {
                output_json_event(json_event);
            }
            buffer.json_event_buffered.clear();
            buffer.event_count = 0;
        }
    }
    g_buffer_lists_mutex.unlock();
}

void bufferring_thread()
{
    std::mutex thread_mutex;
    std::unique_lock<std::mutex> lock(thread_mutex);
    auto time_point = std::chrono::system_clock::now() +
        std::chrono::seconds(g_buffer_lists_timeout_seconds);
    while (!g_buffer_thread_stop) {
        while (g_buffer_list_con_var.wait_until(lock, time_point) == std::cv_status::timeout) {
            flush_buffered_lists();
            time_point = std::chrono::system_clock::now() +
                std::chrono::seconds(g_buffer_lists_timeout_seconds);
        }
    }

    // Flush one last time before ending
    flush_buffered_lists();
}

void start_bufferring()
{
    // Only start buffer thread if we need to
    if (g_buffer_lists.size() != 0 && !g_buffer_thread_stop.load()) {
        g_buffer_list_thread = std::thread(bufferring_thread);
    }
}


void stop_bufferring()
{
    if (g_buffer_lists.size() != 0 && !g_buffer_thread_stop.load()) {
        g_buffer_thread_stop = true;
        g_buffer_list_con_var.notify_one();
        g_buffer_list_thread.join();
    }
}

void print_ppf(ppf_properties_t ppf)
{
    std::cout << "{\n  " << ppf.field_name << ",\n";
    std::vector<std::string>::iterator iter = ppf.field_values.begin();
    std::cout << "  <" << *iter;
    iter++;
    for (; iter != ppf.field_values.end(); iter++) {
        std::cout << ", " << *iter;
    }
    std::cout << ">\n}\n";
}

// Adds given post-processing filter values to global ppf list
void add_ppf_to_list(std::string trace_name, std::string field_name, std::vector<std::string> values_vec)
{
    //ppf_properties_t ppf_properties{ field_name, values_vec };
    //g_ppf_list[trace_name] = ppf_properties;
    g_ppf_list[trace_name] = { field_name, values_vec };

    /*
    // DEV:  print unordered map to confirm contents
    std::cout << "Global list of post-processing filters:\n";
    for (auto iter : g_ppf_list) {
        std::cout << "[" << iter.first << "]: ";
        print_ppf(iter.second);
        std::cout << std::endl;
    }
    */
    return;
}
