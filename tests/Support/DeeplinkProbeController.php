<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Support;

final class DeeplinkProbeController
{
    public function renderAction(\Symfony\Component\HttpFoundation\Request $request): \Symfony\Component\HttpFoundation\Response
    {
        return new \Symfony\Component\HttpFoundation\Response(sprintf(
            '<p><a href="%s">open</a></p>',
            htmlspecialchars((string) $request->attributes->get('deeplink')),
        ));
    }
}
