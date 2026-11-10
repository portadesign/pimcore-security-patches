<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Support;

final class MailProbeController
{
    public function renderAction(\Symfony\Component\HttpFoundation\Request $request): \Symfony\Component\HttpFoundation\Response
    {
        $nicknames = $request->attributes->get('nicknames');

        return new \Symfony\Component\HttpFoundation\Response(sprintf(
            '<p>Hello %s</p><p>Nick %s</p><p>Editor placeholder {{ lastname }}</p><p>Link <a href="https://example.test/?n=%s">x</a></p>',
            htmlspecialchars((string) $request->attributes->get('firstname')),
            htmlspecialchars(is_array($nicknames) ? (string) ($nicknames[0] ?? '') : ''),
            rawurlencode((string) $request->attributes->get('firstname')),
        ));
    }
}
