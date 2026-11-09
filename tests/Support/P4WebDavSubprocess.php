<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Support;

trait P4WebDavSubprocess
{
    /**
     * @return array{status: int, body: string}
     */
    protected function webdavActionRequest(\Pimcore\Model\User $user, string $method, string $path, string $destinationPath): array
    {
        $baseUri = '/admin/asset/webdav/';
        $process = new \Symfony\Component\Process\Process(
            [
                PHP_BINARY,
                __DIR__ . '/p4-webdav-request.php',
                (string) $user->getId(),
                $method,
                $baseUri . ltrim($path, '/'),
                $baseUri . ltrim($destinationPath, '/'),
            ],
            timeout: 120,
        );
        $process->run();

        $output = $process->getOutput();
        $this->assertSame(1, preg_match('/\nHTTP-STATUS:(\d+)\n$/', $output, $matches), 'webdavAction did not report a status: ' . $output . $process->getErrorOutput());

        return ['status' => (int) $matches[1], 'body' => (string) substr($output, 0, -strlen($matches[0]))];
    }
}
