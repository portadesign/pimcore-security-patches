<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('PD-2026-002')]
final class LogMailMaintenanceTest extends \PHPUnit\Framework\TestCase
{
    private const COMPONENT = 'pd-sec-logmail';

    private const ERROR_PRIORITY_FILTER = '3';

    private \Doctrine\DBAL\Connection $db;

    /**
     * @var array<string, mixed>
     */
    private array $originalConfiguration = [];

    /**
     * @var array<int, int|string|null>
     */
    private array $foreignCheckState = [];

    /**
     * @var list<string>
     */
    private array $sentHtml = [];

    private ?\Closure $mailListener = null;

    protected function setUp(): void
    {
        $this->db = \Pimcore\Db::get();
        $this->originalConfiguration = \Pimcore\Config::getSystemConfiguration() ?? [];
        \Pimcore\Config::setSystemConfiguration([
            'mail_notification' => [
                'send_log_summary' => true,
                'mail_receiver' => 'log-receiver@example.test',
                'filter_priority' => self::ERROR_PRIORITY_FILTER,
            ],
        ], 'applicationlog');

        $this->deleteOwnRows();
        $this->foreignCheckState = [];
        $foreignRows = $this->db->fetchAllAssociative(
            'SELECT id, maintenanceChecked FROM application_logs WHERE maintenanceChecked IS NULL OR maintenanceChecked != 1'
        );
        foreach ($foreignRows as $row) {
            $this->foreignCheckState[(int) $row['id']] = $row['maintenanceChecked'];
        }
        $this->db->executeStatement(
            'UPDATE application_logs SET maintenanceChecked = 1 WHERE maintenanceChecked IS NULL OR maintenanceChecked != 1'
        );

        $this->sentHtml = [];
        $this->mailListener = function (\Pimcore\Event\Model\MailEvent $event): void {
            $mail = $event->getMail();
            $this->sentHtml[] = (string) $mail->getHtmlBody();
            $mail->disableLogging();
            $event->setArguments([]);
        };
        \Pimcore::getEventDispatcher()->addListener(\Pimcore\Event\MailEvents::PRE_SEND, $this->mailListener, 1000);
    }

    protected function tearDown(): void
    {
        if (null !== $this->mailListener) {
            \Pimcore::getEventDispatcher()->removeListener(\Pimcore\Event\MailEvents::PRE_SEND, $this->mailListener);
        }

        $this->deleteOwnRows();
        foreach ($this->foreignCheckState as $id => $state) {
            $this->db->executeStatement('UPDATE application_logs SET maintenanceChecked = ? WHERE id = ?', [$state, $id]);
        }
        \Pimcore\Config::setSystemConfiguration($this->originalConfiguration);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function templatePayloadProvider(): array
    {
        return [
            'expression' => ['{{7*7}}', '49'],
            'statement' => ['{% if 1 %}x{% endif %}', 'x'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('templatePayloadProvider')]
    public function testSummaryMailKeepsLoggedMessagesLiteral(string $payload, string $evaluated): void
    {
        $marker = 'pd2026002-' . bin2hex(random_bytes(6));
        $this->insertError($marker . '-' . $payload . '-end');

        (new \Pimcore\Bundle\ApplicationLoggerBundle\Maintenance\LogMailMaintenanceTask($this->db, new \Pimcore\Config()))->execute();

        $this->assertCount(1, $this->sentHtml);
        $this->assertStringContainsString($marker . '-' . $payload . '-end', $this->sentHtml[0]);
        $this->assertStringNotContainsString($marker . '-' . $evaluated . '-end', $this->sentHtml[0]);
    }

    public function testRowsAreMarkedCheckedAfterTheRun(): void
    {
        $this->insertError('{{7*7}} {% if 1 %}x{% endif %}');
        $this->insertError('plain message');

        (new \Pimcore\Bundle\ApplicationLoggerBundle\Maintenance\LogMailMaintenanceTask($this->db, new \Pimcore\Config()))->execute();

        $this->assertSame(
            [1, 1],
            array_map('intval', $this->db->fetchFirstColumn('SELECT maintenanceChecked FROM application_logs WHERE component = ?', [self::COMPONENT])),
        );
        $this->assertCount(1, $this->sentHtml);
    }

    private function insertError(string $message): void
    {
        $this->db->insert('application_logs', [
            'timestamp' => date('Y-m-d H:i:s'),
            'message' => $message,
            'priority' => 'error',
            'component' => self::COMPONENT,
            'source' => 'LogMailMaintenanceTest',
        ]);
    }

    private function deleteOwnRows(): void
    {
        $this->db->executeStatement('DELETE FROM application_logs WHERE component = ?', [self::COMPONENT]);
    }
}
