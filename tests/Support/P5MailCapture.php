<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Support;

trait P5MailCapture
{
    /**
     * @var list<array{text: string, html: string, subject: string, recipients: list<string>}>
     */
    private array $sentMails = [];

    private ?\Closure $mailListener = null;

    protected function captureMails(): void
    {
        $this->sentMails = [];
        $this->mailListener = function (\Pimcore\Event\Model\MailEvent $event): void {
            $mail = $event->getMail();
            $this->sentMails[] = [
                'text' => str_replace("\r\n", "\n", (string) $mail->getTextBody()),
                'html' => (string) $mail->getHtmlBody(),
                'subject' => (string) $mail->getSubject(),
                'recipients' => array_map(
                    static fn (\Symfony\Component\Mime\Address $address): string => $address->getAddress(),
                    $mail->getTo(),
                ),
            ];
            $mail->disableLogging();
            $event->setArguments([]);
        };
        \Pimcore::getEventDispatcher()->addListener(\Pimcore\Event\MailEvents::PRE_SEND, $this->mailListener, 1000);
    }

    protected function releaseMails(): void
    {
        if (null !== $this->mailListener) {
            \Pimcore::getEventDispatcher()->removeListener(\Pimcore\Event\MailEvents::PRE_SEND, $this->mailListener);
            $this->mailListener = null;
        }
    }
}
