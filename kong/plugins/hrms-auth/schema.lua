local PLUGIN_NAME = "hrms-auth"

local schema = {

    name = PLUGIN_NAME,

    fields = {

        {
            config = {

                type = "record",

                fields = {

                    {
                        tenant_header = {

                            type = "string",

                            default = "X-Tenant-Id",

                        },
                    },

                    {
                        auth_header = {

                            type = "string",

                            default = "Authorization",

                        },
                    },

                },
            },
        },

    },
}

return schema