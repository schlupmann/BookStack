<?php

// This is just a sample config. See https://simplesamlphp.org/docs/stable/saml/sp.html for more...

$config = [

    'admin' => [
        'core:AdminPassword',
    ],

    '... enter SP name...' => [
        'saml:SP',
        'entityID' => '...enter the entityID for your SP...',
        'idp' => '...enter IDP url...',
        'privatekey' => 'example.pem',
        'certificate' => 'example.crt',

        'SingleLogoutServiceBinding' => [
            'urn:oasis:names:tc:SAML:2.0:bindings:SOAP',
            'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        ],
        'SingleLogoutServiceLocation' => 'https://example.com/saml2/sls',

        'AssertionConsumerService' => [
            [
                'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                'Location' => 'https://example.com/saml2/login',
                'index' => 0,
            ],
            [
                'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact',
                'Location' => 'https://example.com/saml2/login',
                'index' => 1,
            ],
        ],

        'NameIDFormat' => [
            'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
        ],

        'authproc' => [
          // attributes filter etc...
        ]
    ]
]
