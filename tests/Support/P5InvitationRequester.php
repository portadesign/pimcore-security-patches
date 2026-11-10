<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Support;

trait P5InvitationRequester
{
    /**
     * @param array<string, string> $server
     *
     * @return array{success: bool, message: string}
     */
    protected function invite(string $username, array $server): array
    {
        $request = \Symfony\Component\HttpFoundation\Request::create(
            uri: '/admin/user/invitationlink',
            method: 'POST',
            parameters: ['username' => $username],
            server: $server,
        );

        $container = \Pimcore::getContainer();
        $container->get('request_stack')->push($request);
        $router = $container->get('router');
        \assert($router instanceof \Symfony\Component\Routing\RouterInterface);
        $router->getContext()->fromRequest($request);

        try {
            $controller = $this->adminController(\Pimcore\Bundle\AdminBundle\Controller\Admin\UserController::class);
            $response = $controller->invitationLinkAction($request, $container->get('translator'));
        } finally {
            $container->get('request_stack')->pop();
        }

        $decoded = json_decode((string) $response->getContent(), true, flags: JSON_THROW_ON_ERROR);

        return ['success' => $decoded['success'], 'message' => $decoded['message']];
    }
}
