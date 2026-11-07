using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.Json;
using System.Threading.Tasks;
using StackExchange.Redis;

namespace CacheLab
{
    public interface ICacheProvider
    {
        Task<string?> GetAsync(string key);
        Task SetAsync(string key, string value, TimeSpan ttl);
    }

    public class RedisCacheProvider : ICacheProvider
    {
        private readonly IDatabase _db;
        public RedisCacheProvider(IDatabase db) => _db = db;

        public async Task<string?> GetAsync(string key)
            => await _db.StringGetAsync(key);

        public async Task SetAsync(string key, string value, TimeSpan ttl)
            => await _db.StringSetAsync(key, value, ttl);
    }

    public class VulnerabilityScanner
    {
        public async Task<List<string>> ScanServerAsync(string serverId)
        {
            Console.WriteLine($"[Scanner] Выполняется сканирование сервера {serverId}...");
            await Task.Delay(3000); 

            var events = new List<VulnerabilityEvent>
            {
                new VulnerabilityDetectedEvent("CVE-2024-1234", DateTime.Now.AddDays(-10), "CRITICAL"),
                new VulnerabilityDetectedEvent("CVE-2024-5678", DateTime.Now.AddDays(-5),  "HIGH"),
                new VulnerabilityPatchedEvent ("CVE-2023-9999", DateTime.Now.AddDays(-2),  "PATCH-2024-001")
            };

            var result = new List<string>();
            foreach (var e in events)
                result.Add(e.GetDescription());

            return result;
        }
    }

    class Program
    {
        static async Task Main(string[] args)
        {
            string? choice = args.Length > 0 ? args[0] : null;

            Console.WriteLine("=== CVE Cache Monitor | Вариант 9 ===");

            var redisHost = Environment.GetEnvironmentVariable("REDIS_HOST") ?? "localhost";
            Console.WriteLine($"Подключение к Redis ({redisHost}:6379)...");

            var redis = await ConnectionMultiplexer.ConnectAsync($"{redisHost}:6379,abortConnect=false,connectTimeout=5000");
            var redisDb = redis.GetDatabase();
            ICacheProvider cache = new RedisCacheProvider(redisDb);

            Console.WriteLine("Соединение установлено.");
            Console.WriteLine();

            if (choice == null)
            {
                Console.WriteLine("Выберите режим:");
                Console.WriteLine("  1 - с кешем (Cache-Aside)");
                Console.WriteLine("  0 - без кеша (прямой запрос)");
                Console.Write("Ваш выбор: ");
                choice = Console.ReadLine()?.Trim() ?? "0";
            }
            else
            {
                Console.WriteLine($"Режим (из аргумента): {choice}");
            }

            const string key      = "vulns:server_01";
            const string serverId = "server_01";
            var sw = Stopwatch.StartNew();

            if (choice == "1")
            {
                Console.WriteLine();
                Console.WriteLine("[Cache-Aside] Поиск данных в Redis по ключу: " + key);
                var cached = await cache.GetAsync(key);

                if (cached != null)
                {
                    sw.Stop();
                    Console.WriteLine($"[HIT] Данные найдены в кеше! Время: {sw.ElapsedMilliseconds} мс");
                    Console.WriteLine();
                    var items = JsonSerializer.Deserialize<List<string>>(cached);
                    if (items != null)
                    {
                        Console.WriteLine($"Уязвимости сервера {serverId} (из кеша Redis):");
                        foreach (var item in items)
                            Console.WriteLine($"  - {item}");
                    }
                    return;
                }

                Console.WriteLine("[MISS] Данных в кеше нет. Запуск сканера уязвимостей...");
                Console.WriteLine();
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine("[No-Cache] Режим без кеша. Запуск сканера уязвимостей...");
                Console.WriteLine();
            }

            var scanner = new VulnerabilityScanner();
            var vulns   = await scanner.ScanServerAsync(serverId);
            sw.Stop();

            Console.WriteLine($"[Scanner] Завершено за {sw.ElapsedMilliseconds} мс. Найдено: {vulns.Count} записей.");
            Console.WriteLine();
            Console.WriteLine($"Уязвимости сервера {serverId}:");
            foreach (var v in vulns)
                Console.WriteLine($"  - {v}");

            if (choice == "1")
            {
                Console.WriteLine();
                var json = JsonSerializer.Serialize(vulns);
                await cache.SetAsync(key, json, TimeSpan.FromMinutes(5));
                Console.WriteLine($"[Cache] Данные сохранены в Redis: ключ='{key}', TTL=5 мин.");
            }
        }
    }
}
