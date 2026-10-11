local PLUGIN_NAME = "hrms-auth"

local schema = {

    name = PLUGIN_NAME,

    fields = {

        {
            config = {

                type = "record",

                fields = {

                    {
                        -- No trailing slash: the token issuer
                        -- is compared against
                        -- <keycloak_base_url>/realms/<tenant>.
                        keycloak_base_url = {

                            type = "string",

                            required = true,

                            match = "^https?://.*[^/]$",

                            default = "https://accounts.pp.worksphere.works",

                        },
                    },

                    {
                        client_id = {

                            type = "string",

                            required = true,

                            len_min = 1,

                            default = "hrms-client",

                        },
                    },

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