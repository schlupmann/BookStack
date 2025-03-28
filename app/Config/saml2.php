<?php

$SAML2_IDP_AUTHNCONTEXT = env('SAML2_IDP_AUTHNCONTEXT', true);
$SAML2_SP_x509 = env('SAML2_SP_x509', false);

if (file_exists(base_path('vendor/simplesamlphp/lib/_autoload.php'))) {
    require_once(base_path('vendor/simplesamlphp/lib/_autoload.php'));
}

return [

    // Authentication source for SAML2 option
    'auth_source' => env('SAML2_AUTH_SOURCE', '...enter SP name...'),

    // Display name, shown to users, for SAML2 option
    'name' => env('SAML2_NAME', 'SSO'),

    // Dump user details after a login request for debugging purposes
    'dump_user_details' => env('SAML2_DUMP_USER_DETAILS', false),

    // Attribute, within a SAML response, to find the user's email address
    'email_attribute' => env('SAML2_EMAIL_ATTRIBUTE', 'email'),
    // Attribute, within a SAML response, to find the user's display name
    'display_name_attributes' => explode('|', env('SAML2_DISPLAY_NAME_ATTRIBUTES', 'username')),
    // Attribute, within a SAML response, to use to connect a BookStack user to the SAML user.
    'external_id_attribute' => env('SAML2_EXTERNAL_ID_ATTRIBUTE', null),

    // Group sync options
    // Enable syncing, upon login, of SAML2 groups to BookStack groups
    'user_to_groups' => env('SAML2_USER_TO_GROUPS', false),
    // Attribute, within a SAML response, to find group names on
    'group_attribute' => env('SAML2_GROUP_ATTRIBUTE', 'group'),
    // When syncing groups, remove any groups that no longer match. Otherwise sync only adds new groups.
    'remove_from_groups' => env('SAML2_REMOVE_FROM_GROUPS', false),

    // Autoload IDP details from the metadata endpoint
    'autoload_from_metadata' => env('SAML2_AUTOLOAD_METADATA', false),

    // Overrides, in JSON format, to the configuration passed to underlying library.
    'overrides' => env('SAML2_OVERRIDES', null),

    'security' => [
        // SAML2 Authn context
        'requestedAuthnContext' => is_string(env('SAML2_IDP_AUTHNCONTEXT', true)) ? explode(' ', env('SAML2_IDP_AUTHNCONTEXT', true)) : env('SAML2_IDP_AUTHNCONTEXT', true),
        // Sign requests and responses if a certificate is in use
        'logoutRequestSigned'   => (bool) env('SAML2_SP_x509', false),
        'logoutResponseSigned'  => (bool) env('SAML2_SP_x509', false),
        'authnRequestsSigned'   => (bool) env('SAML2_SP_x509', false),
        'lowercaseUrlencoding'  => false,
    ],

];
