<?php

namespace asd\NID;

require '../vendor/autoload.php';

use asd\NID\Requests\CallbackRequest;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use GuzzleHttp\Client;
use Illuminate\Http\Request;
use Illuminate\Support\Str;


class NIDIntegration
{
    private $clientId;
    private $secret;
    private $redirectUri;
    private $authorizationEndpoint;
    private $tokenEndpoint;


    public function __construct()
    {
        $this->clientId = env('NID_CLIENT_ID');
        $this->secret = env('NID_SECRET');
        $this->authorizationEndpoint = "https://nid.e-gov.am/hy/auth";
        $this->redirectUri = env('NID_REDIRECT_URI');
        $this->tokenEndpoint = "https://nid.e-gov.am/auth/token";
    }

    /**
     * @return string
     */
    public function login(){
        $code_verifier = Str::random(128);
        $code_challenge = strtr(rtrim(base64_encode(hash('sha256', $code_verifier, true)), '='), '+/', '-_');
        $query = http_build_query([
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'response_type' => 'code',
            'scope' => 'openid',
            'state' => $code_verifier,
            'nonce'=> $code_verifier,
            'grant_type' => 'authorization_code',
            'code_challenge' => $code_challenge,
            'code_challenge_method' => 'S256',
        ]);
        $auth_url = "$this->authorizationEndpoint?".$query;
        return $auth_url;
    }

    public function callback(CallbackRequest $request){

        $code = $request->get('code');
        $code_verifier = $request->get('state');
        $token_data = [
            'client_id' => $this->clientId,
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirectUri,
            'code_verifier' => $code_verifier
        ];
        $client_secret = 'Basic ' .$this->secret;
        $headers = [
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Accept' => 'application/json',
            'Authorization' => $client_secret,
        ];
        $client = new Client();
        $token_response = $client->post($this->tokenEndpoint, ['form_params' => $token_data, 'headers' => $headers]);
        $token_info = json_decode($token_response->getBody(), true);
        $jwt_headers = (object)["aud" => "H7XmtnylVn5swpwSReE_2A","algorithm" =>  ["HS512"],"verify_exp" => false];
        $decoded = JWT::decode($token_info['id_token'], new Key($this->secret, 'HS512'), $jwt_headers);
        $profile = json_decode(json_encode($decoded), true)['profile'];
        $profile['access_token'] = $token_info['access_token'];
        if ($token_response->getStatusCode() == 200) {
            $token_info = json_decode($token_response->getBody(), true);
            $jwt_headers = (object)['aud' => $this->clientId, 'algorithm' => ['HS512'], 'verify_exp' => false];
            $decoded = JWT::decode($token_info['id_token'], new Key($this->secret, 'HS512'), $jwt_headers);
            $profile = json_decode(json_encode($decoded), true)['profile'];
            $profile['access_token'] = $token_info['access_token'];
            return $profile;
        }
    }

    /**
     * @param $authorizationEndpoint
     * @return mixed
     */
    public function setAuthorizationEndpoint($authorizationEndpoint = null){
        if($authorizationEndpoint){
            $this->authorizationEndpoint = $authorizationEndpoint;
        }
            return $this->authorizationEndpoint;
    }

    /**
     * @return string
     */
    public function getAuthorizationEndpoint(){
        return $this->authorizationEndpoint;
    }

    /**
     * @param $tokenEndpoint
     * @return mixed
     */
    public function setTokenEndpoint($tokenEndpoint = null){
        if($tokenEndpoint){
            $this->tokenEndpoint = $tokenEndpoint;
        }
        return $this->tokenEndpoint;
    }

    /**
     * @return string
     */
    public function getTokenEndpoint(){
        return $this->tokenEndpoint;
    }

}
