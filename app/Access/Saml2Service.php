<?php

namespace BookStack\Access;

use BookStack\Exceptions\JsonDebugException;
use BookStack\Exceptions\SamlException;
use BookStack\Exceptions\StoppedAuthenticationException;
use BookStack\Exceptions\UserRegistrationException;
use BookStack\Users\Models\User;
use Exception;
use SAML2\Binding;
use SAML2\LogoutRequest;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Store\StoreFactory;
use SimpleSAML\Error\Exception as SimpleSAMLException;
use SimpleSAML\Session;

/**
 * Class Saml2Service
 * Handles any app-specific SAML tasks.
 */
class Saml2Service
{
    protected array $config;
    private static $backChannelSessionId;

    public function __construct(
        protected RegistrationService $registrationService,
        protected LoginService $loginService,
        protected GroupSyncService $groupSyncService
    ) {
        $this->config = config('saml2');
    }

    /**
     * Initiate saml2 login
     */
    public function login()
    {
        $auth = $this->getSimpleSAML();

        $auth->login([
            'ReturnTo' => url('/saml2/processAcs'),
        ]);

        return;
    }

    /**
     * Process authentication after SAML login
     */
    public function processAuthentication()
    {
        $auth = $this->getSimpleSAML();

        Session::getSessionFromRequest()->cleanup();

        $user = $this->processLoginCallback(
            $auth->getAuthData('saml:sp:NameID'),
            $auth->getAttributes()
        );

        session()->put('saml2_session_index', $auth->getAuthData('saml:sp:SessionIndex'));

        $userId = $user->external_auth_id;
        $sessionId = session()->getId();
        
        $samlSession = Session::getSessionFromRequest();
        $samlSession->setData('bookstack', 'bookstack_session', $sessionId);
        $samlSession->setData('bookstack', 'user_id', $userId);
        $samlSessionHandler = \SimpleSAML\SessionHandler::getSessionHandler();
        $samlSessionHandler->saveSession($samlSession);
        
        \SimpleSAML\Session::getSessionFromRequest()->cleanup();

        return $user;
    }

    /**
     * Initiate a logout flow.
     * Returns the SAML2 request ID, and the URL to redirect the user to.
     *
     * @throws SimpleSAMLException
     * @returns array{url: string, id: ?string}
     */
    public function logout(): array
    {
        $auth = $this->getSimpleSAML();
        $returnUrl = url($this->loginService->logout());

        $url = $auth->getLogoutURL($returnUrl);
        $id = session()->getId();

        return ['url' => $url, 'id' => $id];
    }

    /**
     * Handle Single Logout Service requests
     * Processes the logout request and returns appropriate response
     * 
     * @return mixed Response object from SimpleSAMLphp
     */
    public function handleSingleLogout()
    {
        global $sp_sessionId;

        try {
            $config = \SimpleSAML\Configuration::getInstance();
            $session = Session::getSessionFromRequest();
            $spName = config('saml2.auth_source');
            
            // Check if we have an active session (front-channel)
            $isFrontChannel = !is_null($session->getAuthState($spName));
            
            if ($isFrontChannel) {
                // Register front-channel logout handler
                $session->registerLogoutHandler($spName, 'BookStack\Access\Controllers\Saml2Controller', 'logoutFromIdpFrontChannel');
            } else {
                // Handle back-channel logout directly here
                try {
                    $binding = Binding::getCurrentBinding();
                    $message = $binding->receive();
                    
                    if ($message instanceof LogoutRequest) {
                        $nameId = $message->getNameId();
                        $sessionIndexes = $message->getSessionIndexes();
                
                        $config = \SimpleSAML\Configuration::getInstance();
                        $storeType = $config->getOptionalString('store.type', 'phpsession');
                        $store = \SimpleSAML\Store\StoreFactory::getInstance($storeType);
                
                        $strNameId = serialize($nameId);
                        $strNameId = sha1($strNameId);
                        
                        foreach ($sessionIndexes as &$sessionIndex) {
                            if (is_string($sessionIndex) && strlen($sessionIndex) > 50) {
                                $sessionIndex = sha1($sessionIndex);
                            }
                        }
                        unset($sessionIndex);
                
                        if ($store instanceof \SimpleSAML\Store\SQLStore) {
                            $params = [
                                '_authSource' => $spName,
                                '_nameId' => $strNameId,
                            ];
                            
                            $query = 'SELECT _sessionId FROM ' . $store->prefix . '_saml_LogoutStore WHERE _authSource = :_authSource AND _nameId = :_nameId';
                            $stmt = $store->pdo->prepare($query);
                            $stmt->execute($params);
                            $sessionId = $stmt->fetchColumn();
                            
                            if ($sessionId) {
                                // Get the session and register the logout handler
                                $foundSession = Session::getSession($sessionId);
                                $foundSession->registerLogoutHandler($spName, 'BookStack\Access\Controllers\Saml2Controller', 'logoutFromIdpBackChannel');
                                self::$backChannelSessionId = $sessionId;
                            }
                        } else {
                            // Handle other store types if needed... NOT TESTED
                            foreach ($sessionIndexes as $sessionIndex) {
                                $sessionId = $store->get('saml.LogoutStore', $strNameId . ':' . $sessionIndex);
                                if ($sessionId !== null && is_string($sessionId)) {
                                    $foundSession = Session::getSession($sessionId);
                                    $foundSession->registerLogoutHandler($spName, 'BookStack\Access\Controllers\Saml2Controller', 'logoutFromIdpBackChannel');
                                    self::$backChannelSessionId = $sessionId;
                                }
                            }
                        }
                    }
                } catch (\Exception $e) {
                    // Only rethrow if it's not the "no binding found" error
                    if ($e->getMessage() !== 'Unable to find the current binding.') {
                        throw $e;
                    }
                }
            }
            
            // Forward to SimpleSAMLphp SLO handler and get response
            $serviceProvider = new \SimpleSAML\Module\saml\Controller\ServiceProvider($config, $session);
            return $serviceProvider->singleLogoutService($spName);
           
        } catch (\Exception $e) {
            throw $e;
        }
    }


     /**
     * Process a SOAP logout.
     *
     */

     public static function logoutFromIdpBackChannel(): void
     {

        $sp_sessionId = self::$backChannelSessionId;

        if (isset($sp_sessionId)) {
            $config = \SimpleSAML\Configuration::getInstance();
            $storeType = $config->getOptionalString('store.type', 'sql');
            $store = StoreFactory::getInstance($storeType);

            $session = Session::getSession($sp_sessionId);

            $bookstack_sessionId = $session->getData('bookstack', 'bookstack_session');

            if ($store instanceof \SimpleSAML\Store\SQLStore) {
                $store->delete('session', $sp_sessionId);
            }

            $session->cleanup();

            if ($bookstack_sessionId) {
                try {
                    $pdo = null;
                    
                    if (class_exists('\Illuminate\Support\Facades\DB')) {
                        try {
                            $pdo = \Illuminate\Support\Facades\DB::connection()->getPdo();
                        } catch (\Exception $e) {
                            // Connection error handling
                        }
                    }

                    $stmt = $pdo->prepare("SELECT id FROM sessions WHERE id = :id");
                    $stmt->execute(['id' => $bookstack_sessionId]);
                    $sessionExists = $stmt->fetchColumn() !== false;
                    
                    if ($sessionExists) {
                        // Get user ID from SAML session data
                        $userId = $session->getData('bookstack', 'user_id');
                        
                        // Delete the session
                        $stmt = $pdo->prepare("DELETE FROM sessions WHERE id = :id");
                        $stmt->execute(['id' => $bookstack_sessionId]);
                        
                        // Also reset user's remember token if we have their ID
                        if ($userId) {
                            $stmt = $pdo->prepare("UPDATE users SET remember_token = NULL WHERE external_auth_id = :id");
                            $stmt->execute(['id' => $userId]);
                        }
                    }
                } catch (\Exception $e) {
                    // Error handling
                }
            }
        }
     }

    /**
     * Get the metadata for this service provider.
     *
     * @throws SimpleSAMLException
     */
    public function metadata(): string
    {
        try {
            // Get auth source name
            $authSource = $this->config['auth_source'];
            
            // Get the SP auth source
            $source = \SimpleSAML\Auth\Source::getById($authSource);
            if (!($source instanceof \SimpleSAML\Module\saml\Auth\Source\SP)) {
                throw new SimpleSAMLException('Auth source is not a SAML SP');
            }
            
            // Get the metadata URL directly from the SP source
            $metadataUrl = $source->getMetadataURL();
            $metadata = file_get_contents($metadataUrl);
            if (!$metadata) {
                throw new SimpleSAMLException('Failed to fetch metadata from ' . $metadataUrl);
            }
            
            return $metadata;
            
        } catch (\Exception $e) {
            throw new SimpleSAMLException('Error retrieving metadata: ' . $e->getMessage());
        }
    }

    /**
     * Load the SimpleSAMLphp instance.
     *
     * @throws SimpleSAMLException
     */
    protected function getSimpleSAML(): Simple
    {
        $authSource = $this->config['auth_source'];

        return new Simple($authSource);
    }

    /**
     * Check if groups should be synced.
     */
    protected function shouldSyncGroups(): bool
    {
        return $this->config['user_to_groups'] !== false;
    }

    /**
     * Calculate the display name.
     */
    protected function getUserDisplayName(array $samlAttributes, string $defaultValue): string
    {
        $displayNameAttr = $this->config['display_name_attributes'];

        $displayName = [];
        foreach ($displayNameAttr as $dnAttr) {
            $dnComponent = $this->getSamlResponseAttribute($samlAttributes, $dnAttr, null);
            if ($dnComponent !== null) {
                $displayName[] = $dnComponent;
            }
        }

        if (count($displayName) == 0) {
            $displayName = $defaultValue;
        } else {
            $displayName = implode(' ', $displayName);
        }

        return $displayName;
    }

    /**
     * Get the value to use as the external id saved in BookStack
     * used to link the user to an existing BookStack DB user.
     */
    protected function getExternalId(array $samlAttributes, string $defaultValue)
    {
        $userNameAttr = $this->config['external_id_attribute'];
        if ($userNameAttr === null) {
            return $defaultValue;
        }

        return $this->getSamlResponseAttribute($samlAttributes, $userNameAttr, $defaultValue);
    }

    /**
     * Extract the details of a user from a SAML response.
     *
     * @return array{external_id: string, name: string, email: string, saml_id: string}
     */
    protected function getUserDetails(string $samlID, $samlAttributes): array
    {
        $emailAttr = $this->config['email_attribute'];
        $externalId = $this->getExternalId($samlAttributes, $samlID);

        $defaultEmail = filter_var($samlID, FILTER_VALIDATE_EMAIL) ? $samlID : null;
        $email = $this->getSamlResponseAttribute($samlAttributes, $emailAttr, $defaultEmail);

        return [
            'external_id' => $externalId,
            'name'        => $this->getUserDisplayName($samlAttributes, $externalId),
            'email'       => $email,
            'saml_id'     => $samlID,
        ];
    }

    /**
     * Get the groups a user is a part of from the SAML response.
     */
    public function getUserGroups(array $samlAttributes): array
    {
        $groupsAttr = $this->config['group_attribute'];
        $userGroups = $samlAttributes[$groupsAttr] ?? null;

        if (!is_array($userGroups)) {
            $userGroups = [];
        }

        return $userGroups;
    }

    /**
     *  For an array of strings, return a default for an empty array,
     *  a string for an array with one element and the full array for
     *  more than one element.
     */
    protected function simplifyValue(array $data, $defaultValue)
    {
        switch (count($data)) {
            case 0:
                $data = $defaultValue;
                break;
            case 1:
                $data = $data[0];
                break;
        }

        return $data;
    }

    /**
     * Get a property from an SAML response.
     * Handles properties potentially being an array.
     */
    protected function getSamlResponseAttribute(array $samlAttributes, string $propertyKey, $defaultValue)
    {
        if (isset($samlAttributes[$propertyKey])) {
            return $this->simplifyValue($samlAttributes[$propertyKey], $defaultValue);
        }

        return $defaultValue;
    }

    /**
     * Process the SAML response for a user. Login the user when
     * they exist, optionally registering them automatically.
     *
     * @throws SamlException
     * @throws JsonDebugException
     * @throws UserRegistrationException
     * @throws StoppedAuthenticationException
     */
    public function processLoginCallback(string $samlID, array $samlAttributes): User
    {
        $userDetails = $this->getUserDetails($samlID, $samlAttributes);
        $isLoggedIn = auth()->check();

        if ($this->shouldSyncGroups()) {
            $userDetails['groups'] = $this->getUserGroups($samlAttributes);
        }

        if ($this->config['dump_user_details']) {
            throw new JsonDebugException([
                'id_from_idp'         => $samlID,
                'attrs_from_idp'      => $samlAttributes,
                'attrs_after_parsing' => $userDetails,
            ]);
        }

        if ($userDetails['email'] === null) {
            throw new SamlException(trans('errors.saml_no_email_address'));
        }

        if ($isLoggedIn) {
            throw new SamlException(trans('errors.saml_already_logged_in'), '/login');
        }

        $user = $this->registrationService->findOrRegister(
            $userDetails['name'],
            $userDetails['email'],
            $userDetails['external_id']
        );

        if ($this->shouldSyncGroups()) {
            $this->groupSyncService->syncUserWithFoundGroups($user, $userDetails['groups'], $this->config['remove_from_groups']);
        }

        $this->loginService->login($user, 'saml2');

        return $user;
    }
}
