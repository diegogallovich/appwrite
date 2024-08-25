<?php

namespace Appwrite\Auth\OAuth2;

use Appwrite\Auth\OAuth2;

// Reference Material
// https://docs.developers.webflow.com/data/reference/oauth-app

class Webflow extends OAuth2
{
    private string $endpoint = 'https://webflow.com/oauth';
    protected array $user = [];
    protected array $tokens = [];
    protected array $scopes = [
        'assets:read',
        'assets:write',
        'authorized_user:read',
        'cms:read',
        'cms:write',
        'custom_code:read',
        'custom_code:write',
        'forms:read',
        'forms:write',
        'pages:read',
        'pages:write',
        'sites:read',
        'sites:write'
    ];

    public function getName(): string
    {
        return 'webflow';
    }

    public function getLoginURL(): string
    {
        $url = $this->endpoint . '/authorize?' . http_build_query([
            'response_type' => 'code',
            'client_id' => $this->appId,
            'scope' => implode(' ', $this->getScopes()),
            'redirect_uri' => $this->callback,
            'state' => $this->state
        ]);
        return $url;
    }

    protected function getTokens(string $code): array
    {
        if (empty($this->tokens)) {
            $response = $this->request(
                'POST',
                $this->endpoint . '/access_token',
                ['Content-Type: application/json'],
                json_encode([
                    'client_id' => $this->appId,
                    'client_secret' => $this->appSecret,
                    'code' => $code,
                    'redirect_uri' => $this->callback,
                ])
            );

            $this->tokens = json_decode($response, true);
        }

        return $this->tokens;
    }

    public function refreshTokens(string $refreshToken): array
    {
        // Webflow doesn't support refresh tokens, so we'll throw an exception
        throw new \Exception('Webflow does not support refreshing tokens.');
    }

    public function getUserID(string $accessToken): string
    {
        $user = $this->getUser($accessToken);
        return $user['_id'] ?? '';
    }

    public function getUserEmail(string $accessToken): string
    {
        $user = $this->getUser($accessToken);
        return $user['email'] ?? '';
    }

    public function isEmailVerified(string $accessToken): bool
    {
        // Webflow doesn't provide email verification status, so we'll assume it's verified
        return true;
    }

    public function getUserName(string $accessToken): string
    {
        $user = $this->getUser($accessToken);
        return $user['firstName'] . ' ' . $user['lastName'] ?? '';
    }

    protected function getUser(string $accessToken): array
    {
        if (empty($this->user)) {
            $response = $this->request(
                'GET',
                'https://api.webflow.com/user',
                ['Authorization: Bearer ' . $accessToken]
            );

            $this->user = json_decode($response, true);
        }

        return $this->user;
    }
}