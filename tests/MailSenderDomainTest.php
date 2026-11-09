<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('PD-2026-005')]
final class MailSenderDomainTest extends \PHPUnit\Framework\TestCase
{
    private const CONFIGURED_DOMAIN = 'configured.example.test';

    private const REQUEST_HOST = 'other.example.test';

    /**
     * @var array<string, mixed>|null
     */
    private ?array $originalGeneral = null;

    /**
     * @var list<string>
     */
    private array $senders = [];

    private ?\Closure $mailListener = null;

    private int $highestLogIdBefore = 0;

    protected function setUp(): void
    {
        $this->highestLogIdBefore = (int) \Pimcore\Db::get()->fetchOne('SELECT COALESCE(MAX(id), 0) FROM email_log');
        $this->originalGeneral = \Pimcore\Config::getSystemConfiguration('general');

        $this->senders = [];
        $this->mailListener = function (\Pimcore\Event\Model\MailEvent $event): void {
            $mail = $event->getMail();
            $this->senders[] = implode(',', array_map(static fn (\Symfony\Component\Mime\Address $address): string => $address->getAddress(), $mail->getFrom()));
            $mail->disableLogging();
            $event->setArguments([]);
        };
        \Pimcore::getEventDispatcher()->addListener(\Pimcore\Event\MailEvents::PRE_SEND, $this->mailListener, 1000);

        $request = \Symfony\Component\HttpFoundation\Request::create('http://' . self::REQUEST_HOST . '/mail');
        \Pimcore::getContainer()->get('request_stack')->push($request);
    }

    protected function tearDown(): void
    {
        if (null !== $this->mailListener) {
            \Pimcore::getEventDispatcher()->removeListener(\Pimcore\Event\MailEvents::PRE_SEND, $this->mailListener);
        }

        \Pimcore::getContainer()->get('request_stack')->pop();
        \Pimcore\Config::setSystemConfiguration($this->originalGeneral, 'general');
        foreach (\Pimcore\Db::get()->fetchFirstColumn('SELECT id FROM email_log WHERE id > ?', [$this->highestLogIdBefore]) as $id) {
            \Pimcore\Model\Tool\Email\Log::getById((int) $id)?->delete();
        }
    }

    public function testDefaultSenderUsesTheConfiguredDomainNotTheRequestHost(): void
    {
        $this->configureDomain(self::CONFIGURED_DOMAIN);

        $this->sendWithoutSender();

        $this->assertSame(['no-reply@' . self::CONFIGURED_DOMAIN], $this->senders);
    }

    public function testControlDefaultSenderFallsBackToTheRequestHostWithoutConfiguredDomain(): void
    {
        $this->configureDomain('');

        $this->sendWithoutSender();

        $this->assertSame(['no-reply@' . self::REQUEST_HOST], $this->senders);
    }

    public function testControlExplicitSenderIsKept(): void
    {
        $this->configureDomain(self::CONFIGURED_DOMAIN);

        $mail = new \Pimcore\Mail();
        $mail->from('shop@brand.example.test');
        $mail->addTo('recipient@example.test');
        $mail->text('Body');
        $mail->sendWithoutRendering();

        $this->assertSame(['shop@brand.example.test'], $this->senders);
    }

    private function configureDomain(string $domain): void
    {
        \Pimcore\Config::setSystemConfiguration(array_merge($this->originalGeneral ?? [], ['domain' => $domain]), 'general');
    }

    private function sendWithoutSender(): void
    {
        $mail = new \Pimcore\Mail();
        $mail->setIgnoreDebugMode(true);
        $mail->addTo('recipient@example.test');
        $mail->text('Body');
        $mail->sendWithoutRendering();
    }
}
