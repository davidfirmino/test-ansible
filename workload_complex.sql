-- 1. Calculamos os valores aleatórios no CLIENTE (pgbench)
\set aid drandom(1, 100000 * :scale)
\set tid drandom(1, 10 * :scale)

-- 2. Iniciamos a transação
BEGIN;

-- 3. Usamos as variáveis (com o prefixo ':') no SQL
SELECT abalance FROM pgbench_accounts WHERE aid = :aid;

-- Simulamos o "Active Connection" com um delay no cliente
\sleep 50ms

-- Simula a contenção de lock
UPDATE pgbench_tellers SET tbalance = tbalance + 1 WHERE tid = :tid;

END;
