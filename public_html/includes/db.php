<?php
/**
 * VaultFX — PDO Database Connection Singleton
 * ============================================
 * - Prepared statements only (no emulation)
 * - Exception mode enabled
 * - utf8mb4 charset
 * - Singleton pattern to reuse one connection per request
 */

if (!defined('VAULTFX_BOOT')) {
    http_response_code(403);
    exit('Forbidden');
}

class DB
{
    private static ?PDO $instance = null;

    /**
     * Returns the shared PDO connection.
     */
    public static function get(): PDO
    {
        if (self::$instance === null) {
            self::$instance = self::connect();
        }
        return self::$instance;
    }

    /**
     * Creates and configures the PDO connection.
     */
    private static function connect(): PDO
    {
        $dsn = sprintf(
            'mysql:host=%s;port=%s;dbname=%s;charset=%s',
            DB_HOST,
            DB_PORT,
            DB_NAME,
            DB_CHARSET
        );

        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,      // Real prepared statements
            PDO::ATTR_PERSISTENT         => false,      // No persistent connections on shared hosting
            \Pdo\Mysql::ATTR_FOUND_ROWS   => true,       // Consistent rowCount() behavior
            PDO::ATTR_STRINGIFY_FETCHES  => false,
        ];

        try {
            $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);

            // Enforce strict SQL mode for this connection
            $pdo->exec("SET SESSION sql_mode = 'STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'");
            $pdo->exec("SET SESSION time_zone = '+00:00'");

            return $pdo;
        } catch (PDOException $e) {
            // Log but never expose DB credentials or details to the user
            app_log('critical', 'Database connection failed: ' . $e->getMessage());
            http_response_code(503);
            die('Service temporarily unavailable.');
        }
    }

    /**
     * Executes a query and returns the statement.
     *
     * @param  string $sql    Parameterized SQL
     * @param  array  $params Bound parameters
     * @return PDOStatement
     */
    public static function query(string $sql, array $params = []): PDOStatement
    {
        $stmt = self::get()->prepare($sql);
        $stmt->execute($params);
        return $stmt;
    }

    /**
     * Fetches a single row or null.
     */
    public static function row(string $sql, array $params = []): ?array
    {
        $result = self::query($sql, $params)->fetch();
        return $result === false ? null : $result;
    }

    /**
     * Fetches all rows.
     */
    public static function rows(string $sql, array $params = []): array
    {
        return self::query($sql, $params)->fetchAll();
    }

    /**
     * Fetches a single scalar value.
     */
    public static function scalar(string $sql, array $params = [])
    {
        $result = self::query($sql, $params)->fetchColumn();
        return $result === false ? null : $result;
    }

    /**
     * Executes a DML statement and returns rows affected.
     */
    public static function execute(string $sql, array $params = []): int
    {
        return self::query($sql, $params)->rowCount();
    }

    /**
     * Returns last inserted auto-increment ID.
     */
    public static function lastInsertId(): string
    {
        return self::get()->lastInsertId();
    }

    /**
     * Begins a transaction.
     */
    public static function beginTransaction(): void
    {
        self::get()->beginTransaction();
    }

    /**
     * Commits a transaction.
     */
    public static function commit(): void
    {
        self::get()->commit();
    }

    /**
     * Rolls back a transaction.
     */
    public static function rollBack(): void
    {
        if (self::get()->inTransaction()) {
            self::get()->rollBack();
        }
    }

    /**
     * Returns a PDO connection using privileged credentials (install only).
     * Must NOT be used at runtime.
     */
    public static function getInstallConnection(string $host, int $port, string $dbName, string $user, string $pass): PDO
    {
        $dsn = "mysql:host={$host};port={$port};charset=utf8mb4";
        try {
            $pdo = new PDO($dsn, $user, $pass, [
                PDO::ATTR_ERRMODE          => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]);
            return $pdo;
        } catch (PDOException $e) {
            throw new RuntimeException('Install connection failed: ' . $e->getMessage());
        }
    }

    // Prevent instantiation
    private function __construct() {}
    private function __clone() {}
}
