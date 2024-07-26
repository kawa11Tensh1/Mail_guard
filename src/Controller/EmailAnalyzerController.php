<?php
// src/Controller/EmailAnalyzerController.php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class EmailAnalyzerController extends AbstractController
{
    #[Route('/analyze', name: 'email_analyze')]
    public function analyze(Request $request): Response
    {
        // Проверяем, является ли запрос методом POST
        if ($request->isMethod('POST')) {
            // Получаем загруженный файл
            $file = $request->files->get('email');

            // Если файл не загружен, отображаем форму анализа
            if (!$file) {
                return $this->render('email_analyzer/analyze.html.twig');
            }

            // Проверяем, является ли файл валидным EML-файлом
            if ($file->isValid() && $file->getClientOriginalExtension() === 'eml') {
                $filePath = $file->getPathname();
                $emlContent = file_get_contents($filePath);
                $headers = $this->parseEmlHeaders($emlContent);

                // Проверяем наличие заголовка From
                if (isset($headers['From'])) {
                    $fromAddress = $headers['From'];
                    if (is_array($fromAddress)) {
                        $fromAddress = $fromAddress[0]; // Берем первый элемент, если это массив
                    }
                    $domain = $this->extractDomainFromFromHeader($fromAddress);
                    
                    try {
                        // Получаем SPF-запись для домена
                        $spfRecord = $this->getSPFRecord($domain);
                        
                        // Если SPF-запись не найдена, отображаем ошибку
                        if ($spfRecord === null) {
                            return $this->render('email_analyzer/results.html.twig', [
                                'error' => "SPF-запись для домена $domain не найдена.",
                                'fromAddress' => $fromAddress,
                                'domain' => $domain
                            ]);
                        }
                        
                        // Парсим SPF-запись и получаем IP-адреса отправителя
                        $ipRanges = $this->parseSpfRecord($spfRecord);
                        $senderIps = $this->getSenderIps($headers);

                        // Если IP-адреса отправителя не найдены, отображаем ошибку
                        if (empty($senderIps)) {
                            return $this->render('email_analyzer/results.html.twig', [
                                'error' => "IP-адрес отправителя не найден в заголовках.",
                                'fromAddress' => $fromAddress,
                                'domain' => $domain,
                                'spfRecord' => $spfRecord
                            ]);
                        }

                        // Проверяем каждый IP-адрес отправителя на соответствие SPF-записи
                        $results = [];
                        foreach ($senderIps as $senderIp) {
                            $results[] = [
                                'ip' => $senderIp,
                                'is_valid' => $this->isIpInSpfRange($senderIp, $ipRanges),
                            ];
                        }

                        // Отображаем результаты анализа
                        return $this->render('email_analyzer/results.html.twig', [
                            'results' => $results,
                            'fromAddress' => $fromAddress,
                            'domain' => $domain,
                            'spfRecord' => $spfRecord
                        ]);
                    } catch (\Exception $e) {
                        // В случае ошибки при проверке SPF, отображаем сообщение об ошибке
                        return $this->render('email_analyzer/results.html.twig', [
                            'error' => "Ошибка при проверке SPF: " . $e->getMessage(),
                            'fromAddress' => $fromAddress,
                            'domain' => $domain
                        ]);
                    }
                } else {
                    // Если заголовок From не найден, возвращаем ошибку
                    return new Response("Заголовок From не найден.", Response::HTTP_BAD_REQUEST);
                }
            } else {
                // Если формат файла неверный, добавляем flash-сообщение и перенаправляем на страницу анализа
                $this->addFlash('error', 'Неверный формат файла.');
                return $this->redirectToRoute('email_analyze');
            }
        }

        // Если метод запроса не POST, отображаем форму анализа
        return $this->render('email_analyzer/analyze.html.twig');
    }

    // Парсит заголовки EML-файла
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

    // Извлекает домен из заголовка From
    private function extractDomainFromFromHeader(string $fromHeader): string
    {
        // Извлекаем email из заголовка From
        $email = preg_replace('/.*<(.+)>.*/', '$1', $fromHeader);
        
        // Если email не найден в угловых скобках, используем весь fromHeader
        if ($email === $fromHeader) {
            $email = trim($fromHeader);
        }
        
        // Извлекаем домен из email
        $parts = explode('@', $email);
        return array_pop($parts);
    }

    // Получает SPF-запись для домена
    private function getSPFRecord(string $domain): ?string
    {
        $spfRecord = null;
        $error = null;

        // Устанавливаем собственный обработчик ошибок
        set_error_handler(function($errno, $errstr) use (&$error) {
            $error = $errstr;
        });

        try {
            // Получаем DNS-записи для домена
            $dnsRecords = dns_get_record($domain, DNS_TXT);
        } catch (\Exception $e) {
            $error = $e->getMessage();
        }

        // Восстанавливаем стандартный обработчик ошибок
        restore_error_handler();

        if ($error) {
            throw new \RuntimeException("DNS error: $error");
        }

        if ($dnsRecords === false) {
            throw new \RuntimeException("Failed to retrieve DNS records for $domain");
        }

        // Ищем SPF-запись среди DNS-записей
        foreach ($dnsRecords as $record) {
            if (isset($record['txt']) && strpos($record['txt'], 'v=spf1') === 0) {
                $spfRecord = $record['txt'];
                break;
            }
        }

        // Обрабатываем перенаправления в SPF-записи
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

    // Парсит SPF-запись и извлекает диапазоны IP-адресов
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

    // Получает IP-адреса отправителя из заголовков
    private function getSenderIps(array $headers): array
    {
        $senderIps = [];
        $receivedHeaders = isset($headers['Received']) ? (is_array($headers['Received']) ? $headers['Received'] : [$headers['Received']]) : [];
        $receivedHeaders = array_reverse($receivedHeaders);

        foreach ($receivedHeaders as $receivedHeader) {
            // Поиск IPv4 адреса
            if (preg_match('/\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/', $receivedHeader, $matches)) {
                $ip = $matches[0];
                if ($this->validateIp($ip) && !$this->isInternalIp($ip)) {
                    $senderIps[] = $ip;
                    break;
                }
            }

            // Поиск IPv6 адреса
            if (preg_match('/\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/', $receivedHeader, $matches)) {
                $ip = $matches[0];
                if ($this->validateIp($ip) && !$this->isInternalIp($ip)) {
                    $senderIps[] = $ip;
                    break;
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

    // Валидация IP-адреса
    private function validateIp($ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6) !== false;
    }

    // Проверка, является ли IP-адрес внутренним
    private function isInternalIp($ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
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
