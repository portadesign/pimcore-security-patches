<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2023-42817')]
final class SprintfJsTest extends \PHPUnit\Framework\TestCase
{
    private const SOURCE = '/bundles/AdminBundle/Resources/public/js/pimcore/functions.js';

    private ?string $harness = null;

    protected function setUp(): void
    {
        if ('' === trim((string) shell_exec('command -v node 2>/dev/null'))) {
            $this->markTestSkipped('node is not installed on this host; sprintf() in functions.js cannot be executed. Install nodejs to run this test.');
        }
    }

    protected function tearDown(): void
    {
        if (null !== $this->harness && is_file($this->harness)) {
            unlink($this->harness);
        }

        $this->harness = null;
    }

    /**
     * @return array<string, array{list<int|float|string>, string}>
     */
    public static function substitutionInjectionProvider(): array
    {
        return [
            'argument that looks like the next placeholder' => [['a %s b %s', '%s', 'X'], 'a %s b X'],
            'argument that looks like a numeric placeholder' => [['%s and %d', '%d', 5], '%d and 5'],
            'argument that looks like an escaped percent' => [['%s|%s', '100%%', 'x'], '100%%|x'],
            'argument that closes over the remainder' => [['<%s>%s', '%s%s', 'tail'], '<%s%s>tail'],
            'argument that looks like the only placeholder' => [['%s', '%s'], '%s'],
        ];
    }

    /**
     * @param list<int|float|string> $arguments
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('substitutionInjectionProvider')]
    public function testSubstitutedValuesAreNotReinterpretedAsPlaceholders(array $arguments, string $expected): void
    {
        $this->assertSame([$expected], $this->evaluate([$arguments])['results']);
    }

    /**
     * @return array<string, array{list<int|float|string>, string}>
     */
    public static function formatProvider(): array
    {
        return [
            'string' => [['Hello %s!', 'World'], 'Hello World!'],
            'two strings' => [['%s-%s', 'a', 'b'], 'a-b'],
            'integer from numeric string' => [['%d items', '12abc'], '12 items'],
            'integer from garbage' => [['%d items', 'abc'], '0 items'],
            'float with precision' => [['%.1f', 2.46], '2.5'],
            'float without precision' => [['%f', 1.5], '1.5'],
            'literal percent' => [['100%%'], '100%'],
            'percent next to a placeholder' => [['%d%%', 50], '50%'],
            'hex' => [['%x', 255], 'ff'],
            'upper hex' => [['%X', 255], 'FF'],
            'octal' => [['%o', 8], '10'],
            'binary' => [['%b', 5], '101'],
            'character' => [['%c', 65], 'A'],
            'text without placeholder' => [['plain'], 'plain'],
        ];
    }

    /**
     * @param list<int|float|string> $arguments
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('formatProvider')]
    public function testControlRegularFormatsAreUnchanged(array $arguments, string $expected): void
    {
        $this->assertSame([$expected], $this->evaluate([$arguments])['results']);
    }

    public function testControlMissingArgumentIsReportedThroughAlert(): void
    {
        $output = $this->evaluate([['%s %s', 'only']]);

        $this->assertCount(1, $output['alerts']);
        $this->assertStringContainsString('Not enough function arguments', $output['alerts'][0]);
    }

    /**
     * @param list<list<int|float|string>> $calls
     *
     * @return array{results: list<string>, alerts: list<string>}
     */
    private function evaluate(array $calls): array
    {
        $source = (string) file_get_contents(PIMCORE_PATH . self::SOURCE);
        $start = strpos($source, 'sprintf = function');
        $end = strpos($source, 'function array_merge');
        $this->assertNotFalse($start, 'sprintf definition not found in functions.js');
        $this->assertNotFalse($end, 'array_merge marker not found in functions.js');

        $this->harness = (string) tempnam(sys_get_temp_dir(), 'pd-sec-sprintf-');
        file_put_contents($this->harness, "var alerts = [];\nvar alert = function (message) { alerts.push(String(message)); };\n"
            . substr($source, $start, $end - $start)
            . "\nvar calls = JSON.parse(require('fs').readFileSync(0, 'utf8'));\n"
            . "var results = calls.map(function (call) { return sprintf.apply(null, call); });\n"
            . "process.stdout.write(JSON.stringify({results: results, alerts: alerts}));\n");

        $process = proc_open(['node', $this->harness], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        $this->assertIsResource($process);
        fwrite($pipes[0], json_encode($calls, JSON_THROW_ON_ERROR));
        fclose($pipes[0]);
        $stdout = (string) stream_get_contents($pipes[1]);
        $stderr = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exit = proc_close($process);

        $this->assertSame(0, $exit, 'node failed: ' . $stderr);

        return json_decode($stdout, true, flags: JSON_THROW_ON_ERROR);
    }
}
