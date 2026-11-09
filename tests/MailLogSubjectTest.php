<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('PD-2026-002')]
final class MailLogSubjectTest extends \PHPUnit\Framework\TestCase
{
    private int $highestLogIdBefore = 0;

    private ?\Closure $mailListener = null;

    protected function setUp(): void
    {
        $this->highestLogIdBefore = (int) \Pimcore\Db::get()->fetchOne('SELECT COALESCE(MAX(id), 0) FROM email_log');

        $this->mailListener = static function (\Pimcore\Event\Model\MailEvent $event): void {
            $event->setArguments([]);
        };
        \Pimcore::getEventDispatcher()->addListener(\Pimcore\Event\MailEvents::PRE_SEND, $this->mailListener, 1000);
    }

    protected function tearDown(): void
    {
        if (null !== $this->mailListener) {
            \Pimcore::getEventDispatcher()->removeListener(\Pimcore\Event\MailEvents::PRE_SEND, $this->mailListener);
        }

        foreach ($this->createdLogIds() as $id) {
            \Pimcore\Model\Tool\Email\Log::getById($id)?->delete();
        }
    }

    public function testRegularMailLogsItsSubjectRenderedExactlyOnce(): void
    {
        $mail = new \Pimcore\Mail();
        $mail->setIgnoreDebugMode(true);
        $mail->addTo('subject-recipient@example.test');
        $mail->subject('Hello {{ name }}');
        $mail->text('Body for {{ name }}');
        $mail->setParams(['name' => '{{7*7}}']);

        $mail->send();

        $ids = $this->createdLogIds();
        $this->assertCount(1, $ids);
        $this->assertSame('Hello {{7*7}}', \Pimcore\Model\Tool\Email\Log::getById($ids[0])?->getSubject());
    }

    /**
     * @return list<int>
     */
    private function createdLogIds(): array
    {
        return array_map(
            'intval',
            \Pimcore\Db::get()->fetchFirstColumn('SELECT id FROM email_log WHERE id > ? ORDER BY id', [$this->highestLogIdBefore]),
        );
    }
}
