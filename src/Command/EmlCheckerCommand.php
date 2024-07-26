<?php
// src/Command/EmlCheckerCommand.php

namespace App\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(
    name: 'eml:check',
    description: 'Check EML file information',
)]
class EmlCheckerCommand extends Command
{
    protected static $defaultName = 'eml:check';

    protected function configure()
    {
        $this
            ->setDescription('Проверка информации EML файла')
            ->setHelp('Эта команда проверяет EML файл и верифицирует, соответствует ли IP-адрес отправителя SPF-записи.')
            ->addArgument('eml_file', InputArgument::REQUIRED, 'EML файл для проверки');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        // Получение пути к EML файлу
        $emlFilePath = $input->getArgument('eml_file');

        // Проверка существования файла
        if (!file_exists($emlFilePath)) {
            $output->writeln("<error>Файл не найден: $emlFilePath</error>");
            return Command::FAILURE;
        }

        // Чтение содержимого EML файла
        $emlContent = file_get_contents($emlFilePath);
        $headers = $this->parseEmlHeaders($emlContent);

        // Проверка наличия заголовка From
        if (!isset($headers['From'])) {
            $output->writeln("<error>Заголовок From не найден.</error>");
            return Command::FAILURE;
        }

        $fromAddress = $headers['From'];
        if (is_array($fromAddress)) {
            $fromAddress = $fromAddress[0]; // Берем первый элемент, если это массив
        }
        $domain = $this->extractDomainFromFromHeader($fromAddress);
        $output->writeln("<info>Адрес отправителя: $fromAddress</info>");
        $output->writeln("<info>Извлеченный домен: $domain</info>");
    
        try {
            $spfRecord = $this->getSPFRecord($domain);
    
            if ($spfRecord === null) {
                $output->writeln("<error>SPF-запись для домена $domain не найдена.</error>");
            } else {
                $output->writeln("<info>SPF-запись для домена $domain: $spfRecord</info>");
    
                $ipRanges = $this->parseSpfRecord($spfRecord);
                $senderIps = $this->getSenderIps($headers);
    
                // Проверка наличия IP-адресов отправителя
                if (empty($senderIps)) {
                    $output->writeln("<error>IP-адрес отправителя не найден в заголовках.</error>");
                } else {
                    // Проверка соответствия IP-адресов SPF-записи
                    foreach ($senderIps as $senderIp) {
                        $output->writeln("<info>IP-адрес отправителя: $senderIp</info>");
                        if ($this->isIpInSpfRange($senderIp, $ipRanges)) {
                            $output->writeln("<info>IP-адрес отправителя $senderIp соответствует SPF-записи для домена $domain.</info>");
                        } else {
                            $output->writeln("<error>IP-адрес отправителя $senderIp не соответствует SPF-записи для домена $domain.</error>");
                        }
                    }
                }
            }
        } catch (\Exception $e) {
            $output->writeln("<error>Ошибка при проверке SPF: " . $e->getMessage() . "</error>");
        }
    
        return Command::SUCCESS;
    }

    // Парсинг заголовков EML файла
    private function parseEmlHeaders(string $emlContent): array
    {
        $headers = [];
        $lines = explode("\n", $emlContent);
        $currentHeader = '';

        foreach ($lines as $line) {
            // Если строка начинается с пробела или табуляции, это продолжение предыдущего заголовка
            if (preg_match('/^(\s+)(.*)$/', $line, $matches)) {
                if ($currentHeader) {
                    if (is_array($headers[$currentHeader])) {
                        $headers[$currentHeader][count($headers[$currentHeader]) - 1] .= ' ' . trim($matches[2]);
                    } else {
                        $headers[$currentHeader] .= ' ' . trim($matches[2]);
                    }
                }
            } 
            // Иначе это новый заголовок
            elseif (preg_match('/^([^:]+):\s*(.*)$/', $line, $matches)) {
                $currentHeader = $matches[1];
                $headerValue = trim($matches[2]);
                
                if (isset($headers[$currentHeader])) {
                    if (is_array($headers[$currentHeader])) {
                        $headers[$currentHeader][] = $headerValue;
                    } else {
                        $headers[$currentHeader] = [$headers[$currentHeader], $headerValue];
                    }
                } else {
                    $headers[$currentHeader] = $headerValue;
                }
            }
        }

        return $headers;
    }

    // Извлечение домена из заголовка From
    private function extractDomainFromFromHeader(string $fromHeader): string
    {
        // Удаляем возможные имена и оставляем только email
        $email = preg_replace('/.*<(.+)>.*/', '$1', $fromHeader);
        
        // Если email не найден в угловых скобках, используем весь fromHeader
        if ($email === $fromHeader) {
            $email = trim($fromHeader);
        }
        
        // Извлекаем домен из email
        $parts = explode('@', $email);
        return array_pop($parts);
    }

    // Парсинг SPF-записи
    private function parseSpfRecord(string $spfRecord, array &$parsedRecords = []): array
    {
        $ipRanges = [];
        $parts = explode(' ', $spfRecord);

        foreach ($parts as $part) {
            if (strpos($part, 'ip4:') === 0 || strpos($part, 'ip6:') === 0) {
                $ipRanges[] = substr($part, 4);
            } elseif (strpos($part, 'include:') === 0) {
                $includedDomain = substr($part, 8);
                $includedSpfRecord = $this->getSPFRecord($includedDomain);
                if ($includedSpfRecord !== null && !in_array($includedSpfRecord, $parsedRecords)) {
                    $parsedRecords[] = $includedSpfRecord;
                    $ipRanges = array_merge($ipRanges, $this->parseSpfRecord($includedSpfRecord, $parsedRecords));
                }
            }
        }

        return $ipRanges;
    }

    // Получение SPF-записи для домена
    private function getSPFRecord(string $domain): ?string
    {
        $spfRecord = null;
        $error = null;

        // Подавляем предупреждения и ошибки
        set_error_handler(function($errno, $errstr) use (&$error) {
            $error = $errstr;
        });

        try {
            $dnsRecords = dns_get_record($domain, DNS_TXT);
        } catch (\Exception $e) {
            $error = $e->getMessage();
        }

        // Восстанавливаем обработчик ошибок
        restore_error_handler();

        if ($error) {
            throw new \RuntimeException("DNS error: $error");
        }

        if ($dnsRecords === false) {
            throw new \RuntimeException("Failed to retrieve DNS records for $domain");
        }

        foreach ($dnsRecords as $record) {
            if (isset($record['txt']) && strpos($record['txt'], 'v=spf1') === 0) {
                $spfRecord = $record['txt'];
                break;
            }
        }

        // Обработка включенных (include) SPF-записей
        if ($spfRecord !== null) {
            $parts = explode(' ', $spfRecord);
            foreach ($parts as $part) {
                if (strpos($part, 'redirect=') === 0) {
                    $redirectDomain = substr($part, 9);
                    return $this->getSPFRecord($redirectDomain);
                }
            }
        }

        return $spfRecord;
    }

    // Получение IP-адресов отправителя из заголовков
    private function getSenderIps(array $headers): array
    {
        $senderIps = [];

        // Извлечение IP-адресов из заголовков Received
        $receivedHeaders = isset($headers['Received']) ? (is_array($headers['Received']) ? $headers['Received'] : [$headers['Received']]) : [];

        // Обрабатываем заголовки в обратном порядке
        $receivedHeaders = array_reverse($receivedHeaders);

        foreach ($receivedHeaders as $receivedHeader) {
            // Ищем IPv4 адрес
            if (preg_match('/\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/', $receivedHeader, $matches)) {
                $ip = $matches[0];
                if ($this->validateIp($ip) && !$this->isInternalIp($ip)) {
                    $senderIps[] = $ip;
                    break; // Прерываем цикл после нахождения первого валидного внешнего IPv4-адреса
                }
            }

            // Ищем IPv6 адрес
            if (preg_match('/\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/', $receivedHeader, $matches)) {
                $ip = $matches[0];
                if ($this->validateIp($ip) && !$this->isInternalIp($ip)) {
                    $senderIps[] = $ip;
                    break; // Прерываем цикл после нахождения первого валидного внешнего IPv6-адреса
                }
            }
        }

        // Проверка заголовка X-Originating-IP, если IP не найден в заголовках Received
        if (empty($senderIps) && isset($headers['X-Originating-IP'])) {
            $ip = trim($headers['X-Originating-IP'], '[]');
            if ($this->validateIp($ip) && !$this->isInternalIp($ip)) {
                $senderIps[] = $ip;
            }
        }

        return $senderIps;
    }

    // Проверка внутренних IP-адресов
    private function isInternalIp($ip): bool
    {
        // Проверка на локальные и приватные диапазоны IP
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
    }

    // Валидация IP-адреса
    private function validateIp($ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6) !== false;
    }

    // Проверка, находится ли IP-адрес в диапазоне SPF
    private function isIpInSpfRange(string $ip, array $ipRanges): bool
    {
        foreach ($ipRanges as $ipRange) {
            if (strpos($ipRange, '/') !== false) {
                list($network, $prefix) = explode('/', $ipRange);
                if ($this->isIpInCidr($ip, $network, (int)$prefix)) {
                    return true;
                }
            } elseif (strpos($ipRange, '-') !== false) {
                list($start, $end) = explode('-', $ipRange);
                if ($this->isIpInRange($ip, $start, $end)) {
                    return true;
                }
            } elseif ($ip === $ipRange) {
                return true;
            }
        }
        return false;
    }

    // Проверка, находится ли IP-адрес в CIDR диапазоне
    private function isIpInCidr(string $ip, string $network, int $prefix): bool
    {
        $ip = inet_pton($ip);
        $network = inet_pton($network);
        $mask = str_repeat("\xFF", $prefix >> 3) . str_repeat("\x00", 16 - ($prefix >> 3));
        if ($prefix & 7) {
            $mask[$prefix >> 3] = chr(0xFF << (8 - ($prefix & 7)));
        }
        return ($ip & $mask) == ($network & $mask);
    }

    // Проверка, находится ли IP-адрес в заданном диапазоне
    private function isIpInRange(string $ip, string $start, string $end): bool
    {
        $ip = inet_pton($ip);
        $start = inet_pton($start);
        $end = inet_pton($end);
        return ($ip >= $start && $ip <= $end);
    }
}
