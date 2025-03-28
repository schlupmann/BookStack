<?php

namespace BookStack\Access\Controllers;

use BookStack\Access\Saml2Service;
use BookStack\Http\Controller;

class Saml2Controller extends Controller
{
    public function __construct(
        protected Saml2Service $samlService
    ) {
        $this->middleware('guard:saml2');
    }

    /**
     * Start the login flow via SAML2.
     */
    public function login()
    {

        $intendedUrl = redirect()->intended()->getTargetUrl();
 
        $result = $this->samlService->login($intendedUrl);

        return redirect($intendedUrl);

    }

    /**
     * Process SAML authentication after returning from IdP
     */
    public function processAcs()
    {
        try {

            $user = $this->samlService->processAuthentication();
            
            $intendedUrl = redirect()->intended()->getTargetUrl();

            return redirect($intendedUrl);
        } catch (\Exception $e) {
            return redirect('/login')->with('error', 'Authentication failed');
        }
    }

    /**
     * Check if a URL is valid for redirection
     *
     * @param string $url
     * @return bool
     */
    protected function isValidRedirectUrl($url)
    {
        if (empty($url)) {
            return false;
        }

        if (substr($url, 0, 1) === '/') {
            return true;
        }

        $appUrl = config('app.url');
        $parsedAppUrl = parse_url($appUrl);
        $appDomain = $parsedAppUrl['host'] ?? '';

        $parsedUrl = parse_url($url);
        $urlDomain = $parsedUrl['host'] ?? '';

        if (!empty($urlDomain)) {
            return $urlDomain === $appDomain;
        }

        return false;
    }

    /**
     * Start the logout flow via SAML2.
     */
    public function logout()
    {
        $user = user();
        if ($user->isGuest()) {
            return redirect('/login');
        }

        $logoutDetails = $this->samlService->logout($user);

        if ($logoutDetails['id']) {
            session()->flash('saml2_logout_request_id', $logoutDetails['id']);
        }

        return redirect($logoutDetails['url']);
    }

    /**
     * Single logout service.
     * Handle logout requests and responses.
     */
    public function singleLogoutService()
    {
        try {
            // The service handles all the SimpleSAML processing and returns the response
            $response = $this->samlService->handleSingleLogout();
            
            // Process the response
            if (method_exists($response, 'toResponse')) {
                return $response->toResponse();
            } elseif (method_exists($response, 'send')) {
                $response->send();
                exit;
            }
            
            // Fallback
            return redirect('/');
            
        } catch (\Exception $e) {
            return redirect('/');
        }
    }

    /**
     * Handle backchannel logout from the IdP.
     */
    public static function logoutFromIdpBackChannel(): void
    {
        Saml2Service::logoutFromIdpBackChannel();

    }

    /*
    * Get the metadata for this SAML2 service provider.
    */
    public function metadata()
    {
        $metaData = $this->samlService->metadata();

        return response()->make($metaData, 200, [
            'Content-Type' => 'text/xml',
        ]);
    }
    
}
