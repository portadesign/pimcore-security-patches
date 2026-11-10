<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Support;

final class MailProbeController
{
    public function renderAction(\Symfony\Component\HttpFoundation\Request $request): \Symfony\Component\HttpFoundation\Response
    {
        $nicknames = $request->attributes->get('nicknames');
        $engine = \Pimcore::getContainer()->get('pimcore.templating.engine.delegating');
        \assert($engine instanceof \Pimcore\Templating\TwigDefaultDelegatingEngine);
        $twig = $engine->getTwigEnvironment();
        $objectHtml = $twig->createTemplate('{% if object %}<p>Object {{ object.firstname|e }}</p>{% endif %}')->render(['object' => $request->attributes->get('object')]);

        return new \Symfony\Component\HttpFoundation\Response(sprintf(
            '<p>Hello %s</p><p>Raw %s</p>%s<p>Nick %s</p><p>%s</p><p>Link <a href="https://example.test/?n=%s">x</a></p>',
            htmlspecialchars((string) $request->attributes->get('firstname')),
            (string) $request->attributes->get('firstname'),
            $objectHtml,
            htmlspecialchars(is_array($nicknames) ? (string) ($nicknames[0] ?? '') : ''),
            (string) $request->attributes->get('contentDocument')?->getEditable('greeting')?->getData(),
            rawurlencode((string) $request->attributes->get('firstname')),
        ));
    }
}
