-- 1. Calculamos os valores usando 'random' (sem o 'd')
\set aid random(1, 100000 * :scale)
\set tid random(1, 10 * :scale)

-- 2. Fluxo da transação
BEGIN;

-- 3. Consultas
SELECT abalance FROM pgbench_accounts WHERE aid = :aid;

-- Simula o delay de 'Active Connection'
\sleep 50ms

-- Simula a contenção de lock no teller
UPDATE pgbench_tellers SET tbalance = tbalance + 1 WHERE tid = :tid;

END;
