-- Simula uma leitura (AccessShareLock)
BEGIN;
SELECT abalance FROM pgbench_accounts WHERE aid = drandom(1, 100000 * :scale);
-- Simula um pequeno delay para gerar "Active Connection" persistente
\sleep 50ms
-- Simula um UPDATE que gera contenção de lock em uma linha comum
UPDATE pgbench_tellers SET tbalance = tbalance + 1 WHERE tid = drandom(1, 10 * :scale);
END;
