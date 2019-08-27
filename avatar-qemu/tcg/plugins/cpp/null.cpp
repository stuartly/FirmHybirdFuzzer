#include "plugin_api.h"

class plugin_null : public plugin
{
public:
    plugin_null()
        : plugin("null", "does nothing")
    {
    }
};

REGISTER_PLUGIN(plugin_null);
