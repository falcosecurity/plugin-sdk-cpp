#include <falcosecurity/sdk.h>

// todo(jasondellaluce): support these in the SDK
using _et = falcosecurity::event_type;
constexpr auto PPME_SYSCALL_OPEN_E = (_et)2;
constexpr auto PPME_SYSCALL_OPEN_X = (_et)3;
constexpr auto PPME_SYSCALL_OPENAT_E = (_et)102;
constexpr auto PPME_SYSCALL_OPENAT_X = (_et)103;
constexpr auto PPME_SYSCALL_OPENAT_2_E = (_et)306;
constexpr auto PPME_SYSCALL_OPENAT_2_X = (_et)307;
constexpr auto PPME_SYSCALL_OPENAT2_E = (_et)326;
constexpr auto PPME_SYSCALL_OPENAT2_X = (_et)327;
constexpr auto PPME_SYSCALL_OPEN_BY_HANDLE_AT_E = (_et)336;
constexpr auto PPME_SYSCALL_OPEN_BY_HANDLE_AT_X = (_et)337;

class my_plugin
{
    public:
    virtual ~my_plugin() = default;

    std::string get_name() { return "parse-example"; }

    std::string get_version() { return "0.1.0"; }

    std::string get_description() { return "some description"; }

    std::string get_contact() { return "some contact"; }

    // (optional)
    std::vector<falcosecurity::event_type> get_parse_event_types()
    {
        return {
                PPME_SYSCALL_OPEN_E,
                PPME_SYSCALL_OPEN_X,
                PPME_SYSCALL_OPENAT_E,
                PPME_SYSCALL_OPENAT_X,
                PPME_SYSCALL_OPENAT_2_E,
                PPME_SYSCALL_OPENAT_2_X,
                PPME_SYSCALL_OPENAT2_E,
                PPME_SYSCALL_OPENAT2_X,
                PPME_SYSCALL_OPEN_BY_HANDLE_AT_E,
                PPME_SYSCALL_OPEN_BY_HANDLE_AT_X,
        };
    }

    // (optional)
    std::vector<std::string> get_parse_event_sources() { return {"syscall"}; }

    bool init(falcosecurity::init_input& i)
    {
        using st = falcosecurity::state_value_type;
        auto& t = i.tables();
        m_threads_table = t.get_table("threads", st::SS_PLUGIN_ST_INT64);
        m_threads_field_opencount = m_threads_table.add_field(
                t.fields(), "open_evt_count", st::SS_PLUGIN_ST_UINT64);
        return true;
    }

    bool parse_event(const falcosecurity::parse_event_input& in)
    {
        // update counter for current thread
        auto& evt = in.get_event_reader();
        if(evt_type_is_open(evt.get_type()))
        {
            auto& tr = in.get_table_reader();
            auto& tw = in.get_table_writer();

            auto tinfo = m_threads_table.get_entry(tr, (int64_t)evt.get_tid());

            uint64_t count = 0;
            m_threads_field_opencount.read_value(tr, tinfo, count);
            count++;
            m_threads_field_opencount.write_value(tw, tinfo, count);
        }
        return true;
    }

    private:
    inline bool evt_type_is_open(falcosecurity::event_type t)
    {
        return t == PPME_SYSCALL_OPEN_E || t == PPME_SYSCALL_OPEN_X ||
               t == PPME_SYSCALL_OPENAT_E || t == PPME_SYSCALL_OPENAT_X ||
               t == PPME_SYSCALL_OPENAT_2_E || t == PPME_SYSCALL_OPENAT_2_X ||
               t == PPME_SYSCALL_OPENAT2_E || t == PPME_SYSCALL_OPENAT2_X ||
               t == PPME_SYSCALL_OPEN_BY_HANDLE_AT_E ||
               t == PPME_SYSCALL_OPEN_BY_HANDLE_AT_X;
    }

    falcosecurity::table m_threads_table;
    falcosecurity::table_field m_threads_field_opencount;
};

FALCOSECURITY_PLUGIN(my_plugin);
FALCOSECURITY_PLUGIN_EVENT_PARSING(my_plugin);
